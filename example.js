var Cap = require('cap').Cap;
var decoders = require('cap').decoders;
var PROTOCOL = decoders.PROTOCOL;

var c = new Cap();
var device = Cap.findDevice('127.0.0.1');
var filter = 'tcp'; //filters: tcp and dst port 6969
var bufSize = 0;
var buffer = new Buffer(65535);

var linkType = c.open(device, filter, bufSize, buffer);

c.setMinBytes && c.setMinBytes(0);

c.on('packet', function(nbytes, trunc) {  
  
  console.log('\n-------------\n');
	
  if (linkType === 'ETHERNET') {
    var ret = decoders.Ethernet(buffer);

    if (ret.info.type === PROTOCOL.ETHERNET.IPV4) {
      console.log('Decoding IPv4 ...');

      ret = decoders.IPV4(buffer, ret.offset);
      console.log('from: ' + ret.info.srcaddr + ' to ' + ret.info.dstaddr);

      if (ret.info.protocol === PROTOCOL.IP.TCP) {
        var datalen = ret.info.totallen - ret.hdrlen;

        console.log('Decoding TCP ...');

        ret = decoders.TCP(buffer, ret.offset);
        console.log(' from port: ' + ret.info.srcport + ' to port: ' + ret.info.dstport);
        datalen -= ret.hdrlen;
	
	//data length display
	console.log('Data-length: ' + datalen);
	if (datalen === 0){
		//display nothing
		console.log('Content: N.A.');
	} else{
	        console.log('Content: ' + buffer.toString('binary', ret.offset, ret.offset + datalen));
	}
      } else
        console.log('Unsupported IPv4 protocol or UDP connection: ' + PROTOCOL.IP[ret.info.protocol]);
    } else
      console.log('Unsupported Ethertype: ' + PROTOCOL.ETHERNET[ret.info.type]);
  }
});
