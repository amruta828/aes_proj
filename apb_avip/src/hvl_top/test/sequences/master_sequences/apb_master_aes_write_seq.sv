`ifndef APB_MASTER_AES_WRITE_SEQ_INCLUDED_
`define APB_MASTER_AES_WRITE_SEQ_INCLUDED_

//--------------------------------------------------------------------------------------------
// Class: apb_master_aes_write_seq
//  Writes the key, the plaintext and START to the AES accelerator over APB
//--------------------------------------------------------------------------------------------
class apb_master_aes_write_seq extends apb_master_base_seq;
  `uvm_object_utils(apb_master_aes_write_seq)

  // Variable: key
  // 128-bit key to send (default = FIPS-197 C.1 vector)
  bit [127:0] key = 128'h000102030405060708090a0b0c0d0e0f;

  // Variable: pt
  // 128-bit plaintext to send (default = FIPS-197 C.1 vector)
  bit [127:0] pt  = 128'h00112233445566778899aabbccddeeff;

  //-------------------------------------------------------
  // Externally defined Tasks and Functions
  //-------------------------------------------------------
  extern function new(string name = "apb_master_aes_write_seq");
  extern task body();
  extern task apb_write(bit [5:0] addr, bit [31:0] data);

endclass : apb_master_aes_write_seq

//--------------------------------------------------------------------------------------------
// Construct: new
//
// Parameters:
//  name - apb_master_aes_write_seq
//--------------------------------------------------------------------------------------------
function apb_master_aes_write_seq::new(string name = "apb_master_aes_write_seq");
  super.new(name);
endfunction : new

//--------------------------------------------------------------------------------------------
// Task: apb_write
//  Sends one APB write with directed values (no randomize)
//
// Parameters:
//  addr - register address
//  data - 32-bit write data
//--------------------------------------------------------------------------------------------
task apb_master_aes_write_seq::apb_write(bit [5:0] addr, bit [31:0] data);
  req = apb_master_tx::type_id::create("req");
  start_item(req);
  req.pselx  = slave_no_e'(1);              // slave 0, one-hot
  req.paddr  = addr;
  req.pwrite = tx_type_e'(1'b1);            // write
  req.pwdata = data;
  req.pstrb  = 4'hF;
  req.pprot  = protection_type_e'(3'b001);  // privileged
  finish_item(req);
endtask : apb_write

//--------------------------------------------------------------------------------------------
// Task: body
//  Key -> plaintext -> START
//--------------------------------------------------------------------------------------------
task apb_master_aes_write_seq::body();
  super.body();

  // KEY0..KEY3 (KEY0 = least significant word)
  for(int i = 0; i < 4; i++) begin
    apb_write(6'h00 + 4*i, key[32*i +: 32]);
  end

  // PT0..PT3 (PT0 = least significant word)
  for(int i = 0; i < 4; i++) begin
    apb_write(6'h10 + 4*i, pt[32*i +: 32]);
  end

  // CTRL.START
  apb_write(6'h30, 32'h1);

endtask : body

`endif

