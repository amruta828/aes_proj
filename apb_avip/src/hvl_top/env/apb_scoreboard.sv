`ifndef APB_SCOREBOARD_INCLUDED_
`define APB_SCOREBOARD_INCLUDED_

class apb_scoreboard extends uvm_scoreboard;
  `uvm_component_utils(apb_scoreboard)

  // Analysis FIFO for APB Monitor transactions
  uvm_tlm_analysis_fifo#(apb_master_tx) apb_analysis_fifo;
  apb_master_tx tx;

  // Shadow registers to reconstruct keys and plaintexts written via APB
  logic [31:0] key_regs[4]; // KEY0 to KEY3 (0x00 - 0x0C)[cite: 5, 6]
  logic [31:0] pt_regs[4];  // PT0 to PT3   (0x10 - 0x1C)[cite: 5, 6]
  logic [31:0] ct_regs[4];  // CT0 to CT3 captured during readback (0x20 - 0x2C)[cite: 5, 6]

  // Queue to hold expected ciphertexts for multi-block queued operations
  bit [127:0] expected_ct_q[$];

  int tx_count   = 0;
  int pass_count = 0;
  int fail_count = 0;

  // S-box packed as one constant; entry x is at bits [(255-x)*8 +: 8]
  localparam logic [2047:0] SBOX_P = 2048'h637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b27509832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cfd0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdbe0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9ee1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16;

  // Externally defined Tasks and Functions
  extern function new(string name = "apb_scoreboard", uvm_component parent = null);
  extern virtual function void build_phase(uvm_phase phase);
  extern virtual task run_phase(uvm_phase phase);
  extern virtual function void check_phase(uvm_phase phase);
  extern virtual function void report_phase(uvm_phase phase);

  // AES Reference Model Static Methods
 function logic [7:0] sbox(logic [7:0] x);
    return SBOX_P[(255-x)*8 +: 8];
  endfunction

  function logic [7:0] xtime(logic [7:0] a);
    return a[7] ? ((a << 1) ^ 8'h1b) : (a << 1);
  endfunction

function logic [127:0] aes128_encrypt(logic [127:0] key, logic [127:0] pt);
    logic [7:0] st [0:15];
    logic [7:0] tmp [0:15];
    logic [7:0] rk [0:15];
    logic [7:0] nk [0:15];
    logic [7:0] rcon;
    logic [7:0] a0, a1, a2, a3;
    logic [127:0] res;

    for (int i = 0; i < 16; i++) begin
      st[i] = pt [127 - 8*i -: 8];
      rk[i] = key[127 - 8*i -: 8];
    end
    rcon = 8'h01;

    // initial AddRoundKey
    for (int i = 0; i < 16; i++) st[i] = st[i] ^ rk[i];

    for (int rnd = 1; rnd <= 10; rnd++) begin
      // ---- key expansion ----
      nk[0] = rk[0] ^ sbox(rk[13]) ^ rcon;
      nk[1] = rk[1] ^ sbox(rk[14]);
      nk[2] = rk[2] ^ sbox(rk[15]);
      nk[3] = rk[3] ^ sbox(rk[12]);
      for (int i = 4; i < 16; i++) nk[i] = rk[i] ^ nk[i-4];
      for (int i = 0; i < 16; i++) rk[i] = nk[i];
      rcon = xtime(rcon);

      // ---- SubBytes ----
      for (int i = 0; i < 16; i++) st[i] = sbox(st[i]);

      // ---- ShiftRows ----
      for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
          tmp[r + 4*c] = st[r + 4*((c + r) % 4)];
      for (int i = 0; i < 16; i++) st[i] = tmp[i];

      // ---- MixColumns ----
      if (rnd != 10) begin
        for (int c = 0; c < 4; c++) begin
          a0 = st[4*c]; a1 = st[4*c+1]; a2 = st[4*c+2]; a3 = st[4*c+3];
          tmp[4*c]   = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
          tmp[4*c+1] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
          tmp[4*c+2] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
          tmp[4*c+3] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
        end
        for (int i = 0; i < 16; i++) st[i] = tmp[i];
      end

      // ---- AddRoundKey ----
      for (int i = 0; i < 16; i++) st[i] = st[i] ^ rk[i];
    end

    for (int i = 0; i < 16; i++) res[127 - 8*i -: 8] = st[i];
    return res;
  endfunction

endclass : apb_scoreboard

//--------------------------------------------------------------------------------------------
// Constructor: new
//--------------------------------------------------------------------------------------------
function apb_scoreboard::new(string name = "apb_scoreboard", uvm_component parent = null);
  super.new(name, parent);
endfunction : new

//--------------------------------------------------------------------------------------------
// Function: build_phase
//--------------------------------------------------------------------------------------------
function void apb_scoreboard::build_phase(uvm_phase phase);
  super.build_phase(phase);
  apb_analysis_fifo = new("apb_analysis_fifo", this);
endfunction : build_phase

//--------------------------------------------------------------------------------------------
// Task: run_phase
//--------------------------------------------------------------------------------------------
task apb_scoreboard::run_phase(uvm_phase phase);
  super.run_phase(phase);

  forever begin
    apb_analysis_fifo.get(tx);
    tx_count++;

    if (tx.pwrite) begin
      case (tx.paddr)
        6'h00: key_regs[0] = tx.pwdata; // KEY0[cite: 5, 6]
        6'h04: key_regs[1] = tx.pwdata; // KEY1[cite: 5, 6]
        6'h08: key_regs[2] = tx.pwdata; // KEY2[cite: 5, 6]
        6'h0C: key_regs[3] = tx.pwdata; // KEY3[cite: 5, 6]
        6'h10: pt_regs[0]  = tx.pwdata; // PT0 [cite: 5, 6]
        6'h14: pt_regs[1]  = tx.pwdata; // PT1 [cite: 5, 6]
        6'h18: pt_regs[2]  = tx.pwdata; // PT2 [cite: 5, 6]
        6'h1C: pt_regs[3]  = tx.pwdata; // PT3 [cite: 5, 6]
        6'h30: begin                    // CTRL (START trigger)[cite: 6]
          if (tx.pwdata[0]) begin
            bit [127:0] key_in, pt_in, exp_ct;

            key_in = {key_regs[3], key_regs[2], key_regs[1], key_regs[0]};
            pt_in  = {pt_regs[3], pt_regs[2], pt_regs[1], pt_regs[0]};

            exp_ct = aes128_encrypt(key_in, pt_in);
            expected_ct_q.push_back(exp_ct);

            `uvm_info(get_type_name(), $sformatf("AES START Enqueued | Key=0x%0h | PT=0x%0h | Expected CT=0x%0h", key_in, pt_in, exp_ct), UVM_HIGH)
          end
        end
        default: ;
      endcase
    end
    else begin
      case (tx.paddr)
        6'h20: ct_regs[0] = tx.prdata;
        6'h24: ct_regs[1] = tx.prdata;
        6'h28: ct_regs[2] = tx.prdata;
        6'h2C: begin
          ct_regs[3] = tx.prdata;

          begin
            bit [127:0] dut_ct, exp_ct;
            dut_ct = {ct_regs[3], ct_regs[2], ct_regs[1], ct_regs[0]};

            if (expected_ct_q.size() > 0) begin
              exp_ct = expected_ct_q.pop_front();

              if (dut_ct === exp_ct) begin
                `uvm_info("AES_MATCH", $sformatf("SUCCESS: Expected CT = 0x%0h, Got DUT CT = 0x%0h", exp_ct, dut_ct), UVM_LOW)
                pass_count++;
              end else begin
                `uvm_error("AES_MISMATCH", $sformatf("ERROR: Expected CT = 0x%0h, Got DUT CT = 0x%0h", exp_ct, dut_ct))
                fail_count++;
              end
            end else begin
              `uvm_error("UNEXPECTED_READ", "Ciphertext read from DUT without a pending expected transaction in scoreboard queue!")
              fail_count++;
            end
          end
        end
        default: ;
      endcase
    end
  end
endtask : run_phase

//--------------------------------------------------------------------------------------------
// Function: check_phase
//--------------------------------------------------------------------------------------------
function void apb_scoreboard::check_phase(uvm_phase phase);
  super.check_phase(phase);
  if (expected_ct_q.size() > 0) begin
    `uvm_error("SC_CHECK", $sformatf("Scoreboard check failed: %0d unconsumed expected transaction(s) remaining in queue.", expected_ct_q.size()))
  end
  if (fail_count > 0) begin
    `uvm_error("SC_CHECK", $sformatf("Scoreboard check failed with %0d mismatches.", fail_count))
  end else begin
    `uvm_info("SC_CHECK", "Scoreboard check passed successfully.", UVM_LOW)
  end
endfunction : check_phase

//--------------------------------------------------------------------------------------------
// Function: report_phase
//--------------------------------------------------------------------------------------------
function void apb_scoreboard::report_phase(uvm_phase phase);
  super.report_phase(phase);
  `uvm_info(get_type_name(), $sformatf("========================================"), UVM_LOW)
  `uvm_info(get_type_name(), $sformatf("         AES-128 SCOREBOARD REPORT      "), UVM_LOW)
  `uvm_info(get_type_name(), $sformatf("========================================"), UVM_LOW)
  `uvm_info(get_type_name(), $sformatf("Total APB Transactions Processed : %0d", tx_count), UVM_LOW)
  `uvm_info(get_type_name(), $sformatf("Total Ciphertext Matches         : %0d", pass_count), UVM_LOW)
  `uvm_info(get_type_name(), $sformatf("Total Ciphertext Mismatches      : %0d", fail_count), UVM_LOW)
  `uvm_info(get_type_name(), $sformatf("========================================"), UVM_LOW)
endfunction : report_phase

`endif
