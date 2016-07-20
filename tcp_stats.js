var pcap = require('pcap');
var util = require('util');
var colors = require('colors'); //used only to get the output in colored format
var mysql = require('mysql');

var pcapSession = pcap.createSession("", "ip proto \\tcp");

var tcp_tracker = new pcap.TCPTracker();

var start = new Date();
var HOST = '192.168.2.137'; //ip address of machine
var SERVER_PORT = 5252;
var device_ips = [];
var online_status = [];
var device_packets = [0];
var total_devices = 0;
var new_devices = 0;
var prev_devices = 0;

function insert_to_db(device) {
	var con = mysql.createConnection({
        	host : "localhost",
	        user: "root",
        	password: "123",
	        database: "my_db"
	});

	con.connect(function(err){
        	if(err) {
	                console.log('DB Connection Error');
        	        return;
        	}
	});

/*	con.query('INSERT INTO device_list SET ?', device, function(err, res){
                if(err) throw err;
        
		console.log("Last inserted ip: ", res.insertId);
	});
*/
	con.end(function(err){
		//ended
	});

	return null;
}

tcp_tracker.on('session', function(session) {
        session.on('start', function (session) {
//		console.log(session);	
		var source = session.src.split(':')[0];
		var source_port = session.src.split(':')[1];
		console.log("source_port: "+source_port);
		console.log("source: "+source);	
		if (source_port === SERVER_PORT && source_port != null) {
                        var a = device_ips.indexOf(source);
                        if(a === -1) {
				console.log('Device joined: ' + source);
			
				new_devices++;
				total_devices++;
				online_status[total_devices] =  true;
                                device_ips.push(source);
                               
				//insert in database 
//				var dev = { device_ip: source, online_status: online_status[total_devices], packets: 0 };
//				insert_to_db(dev);

                                if(typeof device_packets[a] === undefined) {
                                	device_packets[a] = 0;
                                }
                        }
                }
                var dest = session.dst.split(':')[0];
		var dest_port = session.dst.split(':')[1];
                if (dest === SERVER_PORT) {
                        var a = device_ips.indexOf(dest);
                        if(a === -1) {
				console.log('Device joined: ' + dest);
				new_devices++;
				total_devices++;
				online_status[total_devices] =  true;
                                device_ips.push(dest);
                                
				//insert in db
  //               		var dev = { device_ip: dest, online_status: online_status[total_devices], packets: 0 };
//				insert_to_db(dev);	

		                if(device_packets[total_devices] === undefined) {
                                	device_packets[total_devices] = 0;
                                }
                        }
                }
        });

        session.on('end', function (session) {
        			var source = session.src.split(':')[0];
                		var source_port = session.src.split(':')[1];
				if (session_port == SERVER_PORT) {	
				var a = device_ips.indexOf(source);
		                	if(a != -1 && online_status[a] !=  false) {
						console.log('Device left: '+source);
						online_status[a] =  false;
                			}
				}
		                var dest = session.dst.split(':')[0];
				var dest_port = session.dst.split(':')[1];
                		if (dest_port != SERVER_PORT) {
	                        var a = device_ips.indexOf(dest);
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

var packets_till_now = 0;
var previous_packets_count = 0;
var packet_count = 0;
var total_data_size = 0;
var prev_total_data_size = 0;
//var devices = [];
var index = 0;
pcapSession.on('packet', function(raw_packet) {

	try {
		
		var packet = pcap.decode.packet(raw_packet);
		tcp_tracker.track_packet(packet);

		var ipPacket = findIPv4Packet(packet);
		
		if(ipPacket.payload.sport == 5252 || ipPacket.payload.dport == 5252){

                        console.log(ipPacket);
                }

		//increment packet counter
		packet_count++;

		total_data_size +=  ipPacket.payload.data_bytes;

		var a = device_ips.indexOf(ipPacket.saddr.toString());

		if ( a != -1) {
			
                       device_packets[a] +=  1;
                }
                a = device_ips.indexOf(ipPacket.daddr.toString());
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
	for(var i in device_ips) {
		index++;
		total_device_packets += device_packets[i];
		console.log(colors.blue(index) + '. '.blue+ colors.red(device_ips[i]) + ' online_status: '.blue + colors.red(online_status[i])+' packets: '.blue+colors.red(device_packets[i]));
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
	console.log('Total Devices: '.yellow + colors.red(device_ips.length));
	//packets count and packet flow rate
	packets_till_now = packet_count;
	rate = (packets_till_now - previous_packets_count) / INTERVAL;
	console.log("IPv4 Packets Recived: ".yellow + colors.red(packets_till_now));

	previous_packets_count = packets_till_now;
	console.log("Packets Flow: ".yellow + colors.red(rate) + " packets/sec".yellow);	//rate of packets arriving at a given interval

	//data rate
	data_rate = (total_data_size - prev_total_data_size) / INTERVAL;
	console.log("Data Rate: ".yellow + colors.red(data_rate) + " bytes/sec".yellow);
	prev_total_data_size = total_data_size;

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
