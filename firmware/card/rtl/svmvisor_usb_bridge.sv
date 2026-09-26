`timescale 1ns/1ps
// Fixed 64-byte records, one outstanding command. Faults are configuration-lifetime
// sticky; USB/PCIe resets cannot erase an uncertain command or resynchronize bytes.
module svmvisor_usb_bridge #(
    parameter integer PARTIAL_TIMEOUT_CYCLES=100000000
)(
    input logic usb_clk, enable,
    input logic [31:0] rx_data,
    input logic [3:0] rx_be,
    input logic rx_valid,
    output wire rx_ready,
    output wire [31:0] tx_data,
    output wire tx_valid,
    input logic tx_ready,
    output logic fault=0,
    input logic user_clk,
    output wire [511:0] physical_request,
    output wire physical_valid,
    input logic physical_ready,
    input logic [511:0] physical_response,
    input logic physical_response_valid,
    output wire physical_response_ready,
    input logic board_clk,
    input logic [511:0] snapshot_frame
);
    function automatic [31:0] crc_byte(input [31:0] crc,input [7:0] value);
        logic [31:0] c; c=crc^{24'b0,value};
        for(integer i=0;i<8;i++) c=c[0] ? (c>>1)^32'hedb88320 : c>>1;
        return c;
    endfunction
    function automatic [31:0] crc_word(input [31:0] crc,input [31:0] value);
        logic [31:0] c; c=crc;
        for(integer i=0;i<4;i++) c=crc_byte(c,value[i*8+:8]);
        return c;
    endfunction
    typedef enum logic [3:0] {RECEIVE, CHECK, SEND_PHYSICAL, WAIT_PHYSICAL,
        SEND_IDENTITY, WAIT_IDENTITY, BUILD_IDENTITY, TRANSMIT, RETIRE} state_t;
    state_t state=RECEIVE;
    logic [511:0] incoming=0, outgoing=0, identity=0;
    logic [31:0] receive_crc=32'hffffffff, output_crc=32'hffffffff;
    logic [31:0] sequence_number=0,last_sequence=0;
    logic [31:0] partial_age=0;
    logic [3:0] word_index=0;
    logic [5:0] byte_index=0;
    logic identity_command=0,second_half=0;
    assign rx_ready=enable && !fault && state==RECEIVE;
    assign tx_valid=enable && !fault && state==TRANSMIT;
    assign tx_data=outgoing[word_index*32+:32];

    logic request_send=0;
    logic physical_ack=0;
    wire request_received,physical_request_available;
    assign physical_valid=physical_request_available && !physical_ack;
    always @(posedge user_clk) begin
        if(!physical_request_available) physical_ack<=0;
        else if(physical_valid && physical_ready) physical_ack<=1;
    end
    xpm_cdc_handshake #(.WIDTH(512),.DEST_EXT_HSK(1),.DEST_SYNC_FF(3),
        .SRC_SYNC_FF(3),.INIT_SYNC_FF(1),.SIM_ASSERT_CHK(1)) physical_request_crossing(
        .src_clk(usb_clk),.src_in(incoming),.src_send(request_send),.src_rcv(request_received),
        .dest_clk(user_clk),.dest_out(physical_request),.dest_req(physical_request_available),
        .dest_ack(physical_ack));
    logic response_send=0;
    logic [511:0] response_mailbox=0;
    wire response_received,response_available;
    wire [511:0] response_delivery;
    logic response_ack=0;
    always @(posedge usb_clk) begin
        if(!response_available) response_ack<=0;
        else if(state==WAIT_PHYSICAL && !fault) response_ack<=1;
    end
    assign physical_response_ready=!response_send && !response_received;
    always @(posedge user_clk) begin
        if(response_send) begin if(response_received) response_send<=0; end
        else if(physical_response_valid && physical_response_ready) begin
            response_mailbox<=physical_response; response_send<=1;
        end
    end
    xpm_cdc_handshake #(.WIDTH(512),.DEST_EXT_HSK(1),.DEST_SYNC_FF(3),
        .SRC_SYNC_FF(3),.INIT_SYNC_FF(1),.SIM_ASSERT_CHK(1)) physical_response_crossing(
        .src_clk(user_clk),.src_in(response_mailbox),.src_send(response_send),.src_rcv(response_received),
        .dest_clk(usb_clk),.dest_out(response_delivery),.dest_req(response_available),
        .dest_ack(response_ack));

    logic identity_send=0;
    logic identity_reply_send=0,identity_captured=0;
    wire identity_received,identity_request;
    wire [31:0] identity_nonce;
    xpm_cdc_handshake #(.WIDTH(32),.DEST_EXT_HSK(1),.DEST_SYNC_FF(3),
        .SRC_SYNC_FF(3),.INIT_SYNC_FF(1),.SIM_ASSERT_CHK(1)) identity_request_crossing(
        .src_clk(usb_clk),.src_in(sequence_number),.src_send(identity_send),.src_rcv(identity_received),
        .dest_clk(board_clk),.dest_out(identity_nonce),.dest_req(identity_request),
        .dest_ack(identity_request && identity_captured));
    logic [543:0] identity_mailbox=0;
    wire identity_reply_received,identity_available;
    wire [543:0] identity_delivery;
    logic identity_reply_ack=0;
    always @(posedge usb_clk) begin
        if(!identity_available) identity_reply_ack<=0;
        else if(state==WAIT_IDENTITY && !fault) identity_reply_ack<=1;
    end
    always @(posedge board_clk) begin
        if(!identity_request) identity_captured<=0;
        if(identity_reply_send) begin if(identity_reply_received) identity_reply_send<=0; end
        else if(identity_request && !identity_captured && !identity_reply_received) begin
            // Capture exactly once after the correlated command reaches this domain.
            identity_mailbox<={identity_nonce,snapshot_frame};
            identity_reply_send<=1; identity_captured<=1;
        end
    end
    xpm_cdc_handshake #(.WIDTH(544),.DEST_EXT_HSK(1),.DEST_SYNC_FF(3),
        .SRC_SYNC_FF(3),.INIT_SYNC_FF(1),.SIM_ASSERT_CHK(1)) identity_response_crossing(
        .src_clk(board_clk),.src_in(identity_mailbox),.src_send(identity_reply_send),.src_rcv(identity_reply_received),
        .dest_clk(usb_clk),.dest_out(identity_delivery),.dest_req(identity_available),
        .dest_ack(identity_reply_ack));

    always @(posedge usb_clk) begin
        if(request_send && request_received) request_send<=0;
        if(identity_send && identity_received) identity_send<=0;
        // No reset input intentionally: disconnect, endpoint reset, and stalled clocks
        // never reopen a stream boundary or clear a pending physical observation.
        if(enable && !fault) begin
            case(state)
                RECEIVE: begin
                    if(word_index!=0) begin
                        if(partial_age>=PARTIAL_TIMEOUT_CYCLES-1) fault<=1;
                        else partial_age<=partial_age+1;
                    end
                    if(rx_valid && rx_ready) begin
                        if(rx_be!=4'hf) fault<=1;
                        incoming[word_index*32+:32]<=rx_data;
                        partial_age<=0;
                        if(word_index==15) begin
                            if(rx_data!=~receive_crc) fault<=1;
                            state<=CHECK; word_index<=0;
                        end else begin
                            receive_crc<=crc_word(receive_crc,rx_data);
                            word_index<=word_index+1;
                        end
                    end
                end
                CHECK: begin
                    sequence_number<=incoming[95:64];
                    if(incoming[31:0]!=32'h51525653 || incoming[63:32]!=1 ||
                        incoming[95:64]==0 || incoming[95:64]==last_sequence || incoming[479:256]!=0)
                        fault<=1;
                    else if(incoming[127:96]==2 && incoming[255:128]==0) begin
                        identity_command<=1; second_half<=0; state<=SEND_IDENTITY;
                    end else if(incoming[127:96]==1 && incoming[159:128]>=1 &&
                        incoming[159:128]<=32 && incoming[255:224]!=0 &&
                        ({1'b0,incoming[171:160]}+incoming[159:128])<=4096) begin
                        identity_command<=0; state<=SEND_PHYSICAL;
                    end else fault<=1;
                end
                SEND_PHYSICAL: if(!request_received) begin request_send<=1; state<=WAIT_PHYSICAL; end
                WAIT_PHYSICAL: if(response_available) begin
                    if(response_delivery[95:64]!=sequence_number) fault<=1;
                    else begin outgoing<=response_delivery; word_index<=0; state<=TRANSMIT; end
                end
                SEND_IDENTITY: if(!identity_received) begin identity_send<=1; state<=WAIT_IDENTITY; end
                WAIT_IDENTITY: if(identity_available) begin
                    if(identity_delivery[543:512]!=sequence_number) fault<=1;
                    else begin
                        identity<=identity_delivery[511:0];
                        outgoing<={32'b0,identity_delivery[255:0],64'b0,32'd32,32'b0,
                            sequence_number,32'd1,32'h50525653};
                        output_crc<=32'hffffffff; byte_index<=0; state<=BUILD_IDENTITY;
                    end
                end
                BUILD_IDENTITY: begin
                    if(byte_index==60) begin
                        outgoing[511:480]<=~output_crc; word_index<=0; state<=TRANSMIT;
                    end else begin
                        output_crc<=crc_byte(output_crc,outgoing[byte_index*8+:8]);
                        byte_index<=byte_index+1;
                    end
                end
                TRANSMIT: if(tx_valid && tx_ready) begin
                    if(word_index==15) begin
                        word_index<=0;
                        if(identity_command && !second_half) begin
                            second_half<=1;
                            outgoing<={32'b0,identity[511:256],32'b0,32'd32,32'd32,32'b0,
                                sequence_number,32'd1,32'h50525653};
                            output_crc<=32'hffffffff; byte_index<=0; state<=BUILD_IDENTITY;
                        end else state<=RETIRE;
                    end else word_index<=word_index+1;
                end
                RETIRE: if(!request_send && !request_received && !identity_send &&
                    !identity_received && !identity_available && !response_available) begin
                    last_sequence<=sequence_number; incoming<=0;
                    receive_crc<=32'hffffffff; partial_age<=0; state<=RECEIVE;
                end
                default: fault<=1;
            endcase
        end
    end
endmodule
