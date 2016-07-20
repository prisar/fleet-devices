var pcap = require('pcap');
var util = require('util');
var colors = require('colors');
var pcapSession = pcap.createSession("", "ip proto \\tcp and dst port 80");

var tcp_tracker = new pcap.TCPTracker();

var start = new Date();
/*
tcp_tracker.on('session', function(session) {
	util.inspect(session);
	session.on('start', function (session) {
	    	start = new Date();
		
		console.log("Start of TCP session between " + session.src_name + " and " + session.dst_name + "\n");
	});

	session.on('end', function (session) {
		var end = new Date();
		console.log('Time elapsed: ' + (end - start)/1000 + ' seconds');

	    	console.log("End of TCP session between " + session.src_name + " and " + session.dst_name + "\n");
	});
});
*/

function findIPv4Packet(pcapPacket) {
    if(pcapPacket.link_type === 'LINKTYPE_RAW') {
        return pcapPacket.payload;
    }

    if(pcapPacket.link_type ===  'LINKTYPE_ETHERNET') {
        var packetEthernet = pcapPacket.payload;
        if(packetEthernet.ethertype === 2048) {
            return packetEthernet.payload;
        }
    }
    
    return null;
}

var packetsTillnow = 0;
var previousPacketsCount = 0;
var buffer_size = 10 * 1024 * 1024;
var packetCount = 0;
var totaldata_length = 0;
var prev_total = 0;
var buffer = new Buffer(10);
pcapSession.on('packet', function(raw_packet) {

	try {
		//console.log("Packet stats: " + sys.inspect(stats));		
		var packet = pcap.decode.packet(raw_packet);
		tcp_tracker.track_packet(packet);


		var ipPacket = findIPv4Packet(packet);

		//packet indicator
		if (ipPacket.saddr && ipPacket.daddr) {
			console.log("A Packet came from: ".blue + colors.green(ipPacket.saddr) + " port ".blue + colors.green(ipPacket.payload.sport));
		}
		
		//increment packet counter
		packetCount++;
		//console.log(packetCount++);

		totaldata_length +=  ipPacket.payload.data_bytes;
		//console.log(ipPacket);


		//store data in buffer
		buffer = ipPacket.payload.data;
		if (buffer != null) {
			console.log("Decoded Data: ".blue + colors.grey(buffer.toString()) );
		} else {
			console.log("Decoded Data: Null".blue);
		}

		return console.log("\n");
	} catch (ex) {
		console.log( ex.stack );
	}

});

setInterval(function () {
	console.log('\n-----------------------------------------------------\n'.green);

	//packets count and packet flow rate
	packetsTillnow = packetCount;
	var rate = (packetsTillnow - previousPacketsCount) / 5;
	console.log("Packets:\n Recived tillnow: ".yellow + colors.red(packetsTillnow));

	previousPacketsCount = packetsTillnow;
	console.log("Packets Flow: ".yellow + colors.red(rate) + " packets/sec".blue);	//rate of packets comming at interval of 5 seconds

	//data rate
	var data_rate = (totaldata_length - prev_total) / 5;
	console.log("Data rate: ".yellow + colors.red(data_rate*1024) +" bits/sec".blue);
	prev_total = totaldata_length;
	
	//time
	var end = new Date();
        console.log('Time elapsed: '.yellow + (end - start)/1000 + ' seconds');

	console.log('\n------------------------------------------------------\n'.green);
}, 5000);

setInterval(function () {
	var stats = pcapSession.stats();

	//when dropped
        if (stats.ps_drop > 0 ) {
                console.log("Packet Dropped: " + util.inspect(stats));
        }
}, 5000);
