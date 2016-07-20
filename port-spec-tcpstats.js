var pcap = require('pcap');
var util = require('util');
var colors = require('colors'); //used only to get the output in colored format
var mysql = require('mysql');

var pcapSession = pcap.createSession("", "ip proto \\tcp");

var tcp_tracker = new pcap.TCPTracker();

var start = new Date();
var HOST = '192.168.2.137'; //ip address of machine
var SERVER_PORT = '5252'; //port as string
console.log("Watching: ",HOST+':'+SERVER_PORT);
var device_ips = [];
var online_status = [];
var dev_first_seen = [0];
var dev_last_seen = [0];
var device_packets = [];
var stack_top = -1;
var total_devices = 0;
var new_devices = 0;
var prev_devices = 0;
var device_bit_rates = [0];
var last_device_packets = [0];
var stored_device_bit_rates = [0];

//online_status[0] = true;
device_packets[0] = 0;
var ip_with_port = HOST.concat(':', SERVER_PORT);

function insert_to_db(device) {
	var con = mysql.createConnection({
        	host : "localhost",
	        user: "root",
        	password: "123",
	        database: "my_db"
	});

	con.connect(function(err){
        	if(err) {
        	        return;
        	}
	});

	con.query('INSERT INTO device_list SET ?', device, function(err, res){
                if(err) throw err;
       
	});

	con.end(function(err){
		//
	});

	return null;
}

tcp_tracker.on('session', function(session) {
        session.on('start', function (session) {
		
		var source = session.src.split(':')[0];
		var dest = session.dst.split(':')[0];
  		if( session.dst == ip_with_port) {
                      var a = device_ips.indexOf(source);
                        if(a === -1) {
				console.log('Device joined: '+source);
			
				new_devices++;
				total_devices++;
				stack_top++;
				online_status[stack_top] =  true;
                                device_ips.push(source);
                                
				if(typeof device_packets[stack_top] === undefined || isNaN(device_packets[stack_top])
						|| isNaN(device_bit_rates[stack_top])) {
                                	device_packets[a] = 0;
					device_bit_rates[a] = 0;
                                }

				dev_first_seen[stack_top] = new Date();
                        }
                }

		if( session.src == ip_with_port) {  
                      var a = device_ips.indexOf(dest);
                        if(a === -1) {
				console.log('Device joined: '+dest);
				new_devices++;
				total_devices++;
				online_status[total_devices] =  true;
                                device_ips.push(dest);
                                
		                if(device_packets[total_devices] === undefined || isNaN(device_packets[a])
					|| isNaN(device_bit_rates[total_devices])) {
                                	device_packets[total_devices] = 0;
                                }

                                dev_first_seen[total_devices] = new Date();

                        }
                }
        });

        session.on('end', function (session) {
				var source = session.src.split(':')[0];
				var dest = session.dst.split(':')[0];
        			if (session.dst == ip_with_port) {
                		        var a = device_ips.indexOf(source);
		                        if(a != -1 && online_status[a] !=  false) {
					console.log('Device left: '+source);
					online_status[a] =  false;
                                        dev_last_seen[a] = new Date();
					}

				}
                		if (session.src == ip_with_port) {
	        	                var a = device_ips.indexOf(dest);
        	        	        if(a != -1 && online_status[a] !=  false) {
					console.log("Device left: "+dest);
					online_status[a] =  false;
					dev_last_seen[a] = new Date();
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
var packetCount = 0;
var totaldata_length = 0;
var prev_total = 0;
var index = 0;
pcapSession.on('packet', function(raw_packet) {

	try {
		
		var packet = pcap.decode.packet(raw_packet);
		tcp_tracker.track_packet(packet);

		var ipPacket = findIPv4Packet(packet);

		//increment packet counter
		packetCount++;

		totaldata_length +=  ipPacket.payload.data_bytes;

	        a = device_ips.indexOf(ipPacket.saddr.toString());
		b = device_ips.indexOf(ipPacket.daddr.toString());
                	
		if(isNaN(ipPacket.payload.sport)  || isNaN(ipPacket.payload.dport) ) {
			return ;
		}
	
		if (ipPacket.payload.sport == SERVER_PORT  || ipPacket.payload.dport == SERVER_PORT) {
			if (a != -1) {
                        	device_packets[a] +=  1;
                	}
			if (b != -1) {
				device_packets[b] += 1;
			}
		}


	} catch (ex) {
		console.log( ex.stack );
	}

});

var rate = 0;
var data_rate = 0;
var INTERVAL = 5000;
setInterval(function () {
	console.log('\n================================================================================================\n'.green);

	console.log('Device List: '.yellow);
	var index = 0;
	var total_device_packets = 0;
	for(var i in device_ips) {
		index++;
		total_device_packets += device_packets[i];

		device_bit_rates[i] = (device_packets[i] - last_device_packets[i])/INTERVAL;
		stored_device_bit_rates[i] = device_bit_rates[i];
		last_device_packets[i] = device_packets[i];
		
		console.log(colors.blue(index) + '. '.blue+ colors.red(device_ips[i]) 
				+' online_status: '.blue + colors.red(online_status[i])
//				+' first_seen: '.blue + colors.red(dev_first_seen[i])
//				+' last_seen: '.blue + colors.red(dev_last_seen[i])
				+' packets: '.blue+colors.red(device_packets[i])
				+' bit_rate: '.blue+colors.red(device_bit_rates[i]));

		//insert in database
                var dev = { device_ip: device_ips[i],
				first_seen: dev_first_seen[i], last_seen: dev_last_seen[i], 
				online_status: online_status[i],
				packets: device_packets[i],
 				bit_rate: device_bit_rates[i] 
				};
                insert_to_db(dev);

	}
	console.log("Total Packets from these devices: ".yellow+colors.red(total_device_packets));
	console.log('New Devices: '.yellow + colors.red(new_devices - prev_devices));
	
	//TODO check online_status
	var online_devices = 0;
	var offline_devices = 0;
	var totaldevices = device_ips.length;
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
	
	var totaldevices = device_ips.length;
	prev_devices = new_devices;
	console.log('Total Devices: '.yellow + colors.red(totaldevices));
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
        
        
	console.log('\n================================================================================================\n'.green);
}, INTERVAL);

setInterval(function () {
	var stats = pcapSession.stats();

	//when dropped
        if (stats.ps_drop > 0 ) {
                console.log("Packets are dropped and session stat is: " + util.inspect(stats));
        }
}, 600000);
