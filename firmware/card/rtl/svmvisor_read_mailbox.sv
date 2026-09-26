`timescale 1ns/1ps
// USER4 commands one bounded slot; it never originates a PCIe transaction.
// Full CRC-checked scans cross by acknowledged mailbox. BAR response publication
// is atomic after all words, matching sequence and CRC. PCIe reset cancels staging.
module svmvisor_read_mailbox #(
    parameter bit USB_ENABLED=0
)(
    input logic user_clk, transaction_reset,
    input logic write_valid, bad_alignment,
    input logic [11:0] write_address, read_address,
    input logic [31:0] write_data,
    input logic [3:0] write_be,
    output logic [31:0] read_data,
    input logic drck, capture, shift, selected, tdi,
    output logic tdo,
    input logic [511:0] usb_request,
    input logic usb_request_valid,
    output wire usb_request_ready,
    output logic [511:0] usb_response=0,
    output logic usb_response_valid=0,
    input logic usb_response_ready
);
    localparam [31:0] REQUEST_MAGIC=32'h51525653, RESPONSE_MAGIC=32'h50525653;
    function automatic [31:0] crc_byte(input [31:0] crc,input [7:0] value);
        logic [31:0] c; c=crc^{24'b0,value};
        for(integer i=0;i<8;i++) c=c[0] ? (c>>1)^32'hedb88320 : c>>1;
        return c;
    endfunction
    logic [9:0] scan_index=0;
    logic [511:0] incoming=0,request_mailbox=0;
    logic [31:0] request_crc=32'hffffffff;
    logic request_send=0;
    wire request_received,request_ready;
    wire mailbox_busy,scan_busy;
    wire [511:0] request_delivery;
    wire [511:0] complete_scan={tdi,incoming[511:1]};
    always @(posedge drck) begin
        if(request_send && request_received) request_send<=0;
        if(selected && capture) begin
            scan_index<=0; incoming<=0; request_crc<=32'hffffffff;
        end else if(selected && shift && scan_index<512) begin
            incoming<=complete_scan; scan_index<=scan_index+1;
            if(scan_index<480)
                request_crc<=(request_crc[0]^tdi) ? (request_crc>>1)^32'hedb88320 : request_crc>>1;
            if(scan_index==511 && !request_send && !request_received && !scan_busy &&
                complete_scan[31:0]==REQUEST_MAGIC && complete_scan[63:32]==1 &&
                complete_scan[95:64]!=0 && complete_scan[511:480]==~request_crc) begin
                request_mailbox<=complete_scan; request_send<=1;
            end
        end
    end
    xpm_cdc_single #(.DEST_SYNC_FF(3),.INIT_SYNC_FF(1),.SRC_INPUT_REG(1)) busy_crossing(
        .src_clk(user_clk),.src_in(mailbox_busy),.dest_clk(drck),.dest_out(scan_busy));
    xpm_cdc_handshake #(.WIDTH(512),.DEST_EXT_HSK(0),.DEST_SYNC_FF(3),
        .SRC_SYNC_FF(3),.INIT_SYNC_FF(1),.SIM_ASSERT_CHK(1)) request_crossing(
        .src_clk(drck),.src_in(request_mailbox),.src_send(request_send),.src_rcv(request_received),
        .dest_clk(user_clk),.dest_out(request_delivery),.dest_req(request_ready),.dest_ack(1'b0));

    logic [511:0] request=0,response=0,staging=0,candidate=0;
    logic [31:0] active_sequence=0,last_sequence=0;
    logic usb_owner=0;
    assign mailbox_busy=active_sequence!=0 || usb_response_valid;
    assign usb_request_ready=USB_ENABLED && !transaction_reset && !bad_alignment &&
        !mailbox_busy && !request_ready;
    logic [15:0] staged_valid=0;
    logic building=0;
    logic [5:0] byte_index=0;
    logic [31:0] response_crc=32'hffffffff;
    always @(posedge user_clk) begin
        if(USB_ENABLED && usb_response_valid && usb_response_ready) usb_response_valid<=0;
        if(transaction_reset || bad_alignment) begin
            staged_valid<=0; building<=0;
        end else begin
            if(request_ready && !mailbox_busy && request_delivery[95:64]!=last_sequence) begin
                request<=request_delivery; active_sequence<=request_delivery[95:64];
                last_sequence<=request_delivery[95:64]; staged_valid<=0; usb_owner<=0;
            end else if(USB_ENABLED && usb_request_valid && usb_request_ready) begin
                request<=usb_request; active_sequence<=usb_request[95:64];
                last_sequence<=usb_request[95:64]; staged_valid<=0; usb_owner<=1;
            end
            if(building) begin
                if(byte_index==60) begin
                    if(candidate[511:480]==~response_crc) begin
                        response<=candidate; active_sequence<=0;
                        if(usb_owner) begin usb_response<=candidate; usb_response_valid<=1; end
                    end
                    building<=0;
                end else begin
                    response_crc<=crc_byte(response_crc,candidate[byte_index*8+:8]);
                    byte_index<=byte_index+1;
                end
            end else if(write_valid) begin
                if(write_address[1:0]!=0 || write_be!=4'hf) staged_valid<=0;
                else if(write_address>=12'h540 && write_address<12'h580) begin
                    staging[(write_address-12'h540)*8+:32]<=write_data;
                    staged_valid[(write_address-12'h540)>>2]<=1;
                end else if(write_address==12'h580) begin
                    staged_valid<=0;
                    if(staged_valid==16'hffff && active_sequence!=0 &&
                        write_data==active_sequence && staging[95:64]==active_sequence &&
                        staging[31:0]==RESPONSE_MAGIC && staging[63:32]==1) begin
                        candidate<=staging; response_crc<=32'hffffffff;
                        byte_index<=0; building<=1;
                    end
                end else staged_valid<=0;
            end
        end
    end
    always @* begin
        read_data=0;
        if(read_address[1:0]==0) begin
            if(read_address>=12'h500 && read_address<12'h540)
                read_data=request[(read_address-12'h500)*8+:32];
            else if(read_address>=12'h540 && read_address<12'h580)
                read_data=response[(read_address-12'h540)*8+:32];
            else case(read_address)
                12'h584: read_data=32'h31525653;
                12'h588: read_data=active_sequence;
                12'h58c: read_data=response[95:64];
                default: read_data=0;
            endcase
        end
    end
    logic response_send=0;
    logic [511:0] response_mailbox=0;
    wire response_received,response_ready;
    wire [511:0] response_delivery;
    always @(posedge user_clk) begin
        if(response_send) begin if(response_received) response_send<=0; end
        else if(!response_received && response_mailbox!=response) begin
            response_mailbox<=response; response_send<=1;
        end
    end
    xpm_cdc_handshake #(.WIDTH(512),.DEST_EXT_HSK(0),.DEST_SYNC_FF(3),
        .SRC_SYNC_FF(3),.INIT_SYNC_FF(1),.SIM_ASSERT_CHK(1)) response_crossing(
        .src_clk(user_clk),.src_in(response_mailbox),.src_send(response_send),.src_rcv(response_received),
        .dest_clk(drck),.dest_out(response_delivery),.dest_req(response_ready),.dest_ack(1'b0));
    logic [511:0] response_mirror=0,scan_bits=0;
    always @(posedge drck) begin
        if(response_ready) response_mirror<=response_delivery;
        if(selected && capture) scan_bits<=response_mirror;
        else if(selected && shift) scan_bits<={1'b0,scan_bits[511:1]};
    end
    assign tdo=scan_bits[0];
endmodule
