var pcap = require('pcap');
var util = require('util');
var colors = require('colors'); //used only to get the output in colored format
var pcapSession = pcap.createSession("", "ip proto \\tcp");

var tcp_tracker = new pcap.TCPTracker();

var start = new Date();
var HOST = '192.168.2.137'; //ip address of machine
var table = [];
var online_status = [];
var device_packets = [0];
var total_devices = 0;
var new_devices = 0;
var prev_devices = 0;

tcp_tracker.on('session', function(session) {
        session.on('start', function (session) {
		
		var source = session.src.split(':')[0];
		if (session.src != HOST && source.search(/192.168./g) === -1) {
                        var a = table.indexOf(source);
                        if(a === -1) {
				console.log('Device joined: '+source);
				new_devices++;
				total_devices++;
				online_status[total_devices] =  true;
                                table.push(source);
                                
                                if(typeof device_packets[a] === undefined) {
                                	device_packets[a] = 0;
                                }
                        }
                }
                var dest = session.dst.split(':')[0];
                if (session.dst != HOST && dest.search(/192.168./g) === -1) {
                        var a = table.indexOf(dest);
                        if(a === -1) {
				console.log('Device joined: '+dest);
				new_devices++;
				total_devices++;
				online_status[total_devices] =  true;
                                table.push(dest);
                                
                                if(device_packets[total_devices] === undefined) {
                                	device_packets[total_devices] = 0;
                                }
                        }
                }
        });

        session.on('end', function (session) {
        			var source = session.src.split(':')[0];
                		        var a = table.indexOf(source);
		                        if(a != -1 && online_status[a] !=  false) {
					console.log('Device left: '+source);
					online_status[a] =  false;
                		}
		                var dest = session.dst.split(':')[0];
                		if (session.dst != HOST && dest.search(/192.168./g) === -1) {
	                        var a = table.indexOf(dest);
        	                if(a != -1 && online_status[a] !=  false) {
					console.log("Device left: "+dest);
					online_status[a] =  false;
        	                	}
                		}
        });
});

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
//var buffer_size = 10 * 1024 * 1024;
var packetCount = 0;
var totaldata_length = 0;
var prev_total = 0;
//var buffer = new Buffer(65535);
var devices = ["127.0.0.1"];
var index = 0;
pcapSession.on('packet', function(raw_packet) {

	try {
		
		var packet = pcap.decode.packet(raw_packet);
		tcp_tracker.track_packet(packet);


		var ipPacket = findIPv4Packet(packet);

		//increment packet counter
		packetCount++;
		//console.log(packetCount++);

		totaldata_length +=  ipPacket.payload.data_bytes;
		//console.log(ipPacket);

		var a = table.indexOf(ipPacket.saddr.toString());
		if ( a != -1) {
			
                       device_packets[a] +=  1;
                }
                a = table.indexOf(ipPacket.daddr.toString());
                if (a != -1) {
                        device_packets[a] +=  1;
                }

	} catch (ex) {
		console.log( ex.stack );
	}

});

var rate = 0;
var data_rate = 0;
var INTERVAL = 5000;
setInterval(function () {
	console.log('\n=======================================================================\n'.green);

	console.log('Device List: '.yellow);
	var index = 0;
	var total_device_packets = 0;
	for(var i in table) {
		index++;
		total_device_packets += device_packets[i];
		console.log(colors.blue(index) + '. '.blue+ colors.red(table[i]) + ' online_status: '.blue + colors.red(online_status[i])+' packets: '.blue+colors.red(device_packets[i]));
	}
	console.log("Total Packets from these devices: ".yellow+colors.red(total_device_packets));
	console.log('New Devices: '.yellow + colors.red(new_devices - prev_devices));
	
	//TODO check online_status
	var online_devices = 0;
	var offline_devices = 0;
	for(var i in online_status) {
		if( online_status[i] === true) {
			online_devices++;
		}
		if( online_status[i] === false) {
			offline_devices++;
		}
	}
	console.log('Online Devices: '.yellow+ colors.red(online_devices));
	console.log('Offline Devices: '.yellow+ colors.red(offline_devices));
	
	prev_devices = new_devices;
	console.log('Total Devices: '.yellow + colors.red(table.length));
	//packets count and packet flow rate
	packetsTillnow = packetCount;
	rate = (packetsTillnow - previousPacketsCount) / INTERVAL;
	console.log("IPv4 Packets Recived: ".yellow + colors.red(packetsTillnow));

	previousPacketsCount = packetsTillnow;
	console.log("Packets Flow: ".yellow + colors.red(rate) + " packets/sec".yellow);	//rate of packets arriving at a given interval

	//data rate
	data_rate = (totaldata_length - prev_total) / INTERVAL;
	console.log("Data Rate: ".yellow + colors.red(data_rate) + " bytes/sec".yellow);
	prev_total = totaldata_length;

	//time
	var end = new Date();
        console.log('Start Time: '.yellow + colors.red(start) );
        console.log('Time Now: '.yellow + colors.red(end) );
        console.log('Time Elapsed: '.yellow + colors.red((end - start)/1000) + ' seconds'.yellow);
        
        
	console.log('\n=======================================================================\n'.green);
}, INTERVAL);

setInterval(function () {
	var stats = pcapSession.stats();

	//when dropped
        if (stats.ps_drop > 0 ) {
                console.log("Packet Dropped: " + util.inspect(stats));
        }
}, 5000);
