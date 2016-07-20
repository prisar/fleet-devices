var pcap = require('pcap');
var util = require('util');
var tcp_tracker = new pcap.TCPTracker();
var pcap_session = pcap.createSession("", "ip proto \\tcp");

    tcp_tracker.on('session', function (session) {
        session.on('start', function (session) {
		console.log("Start of TCP session between " + session.src_name + " and " + session.dst_name);
    });

    	session.on('end', function (session) {
	        console.log("End of TCP session between " + session.src_name + " and " + session.dst_name);
    });
    });

    var mySession = pcap_session.on('packet', function (raw_packet) {
        var packet = pcap.decode.packet(raw_packet);
	tcp_tracker.track_packet(packet);
	util.inspect(packet);
//	console.log("Packet: \n" + packet);
    });
