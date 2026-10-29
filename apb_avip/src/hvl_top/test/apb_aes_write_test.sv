`ifndef APB_AES_WRITE_TEST_INCLUDED_
`define APB_AES_WRITE_TEST_INCLUDED_

//--------------------------------------------------------------------------------------------
// Class: apb_aes_write_test
//  Sends key, plaintext and START to the AES accelerator
//--------------------------------------------------------------------------------------------
class apb_aes_write_test extends apb_base_test;
  `uvm_component_utils(apb_aes_write_test)

  // Variable: apb_master_aes_write_seq_h
  apb_master_aes_write_seq apb_master_aes_write_seq_h;

  //-------------------------------------------------------
  // Externally defined Tasks and Functions
  //-------------------------------------------------------
  extern function new(string name = "apb_aes_write_test", uvm_component parent = null);
  extern virtual task run_phase(uvm_phase phase);

endclass : apb_aes_write_test

//--------------------------------------------------------------------------------------------
// Construct: new
//
// Parameters:
//  name   - apb_aes_write_test
//  parent - parent under which this component is created
//--------------------------------------------------------------------------------------------
function apb_aes_write_test::new(string name = "apb_aes_write_test", uvm_component parent = null);
  super.new(name, parent);
endfunction : new

//--------------------------------------------------------------------------------------------
// Task: run_phase
//  Creates and starts the sequence on the master sequencer
//
// Parameters:
//  phase - uvm phase
//--------------------------------------------------------------------------------------------
task apb_aes_write_test::run_phase(uvm_phase phase);

  apb_master_aes_write_seq_h = apb_master_aes_write_seq::type_id::create("apb_master_aes_write_seq_h");

  phase.raise_objection(this, "apb_aes_write_test");

  // Optional: override the data (defaults are the FIPS-197 C.1 vector)
  // apb_master_aes_write_seq_h.key = 128'h...;
  // apb_master_aes_write_seq_h.pt  = 128'h...;

  `uvm_info(get_type_name(), "Starting apb_master_aes_write_seq", UVM_LOW)
  apb_master_aes_write_seq_h.start(apb_env_h.apb_master_agent_h.apb_master_seqr_h);

  // Give the DUT time to finish (command FIFO, AES core, response FIFO)
  #1us;

  phase.drop_objection(this, "apb_aes_write_test");

endtask : run_phase

`endif
