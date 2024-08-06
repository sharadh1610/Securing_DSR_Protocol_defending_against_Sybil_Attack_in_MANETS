

#Fixing the co-ordinate of simulation area
set val(x) 500
set val(y) 500
# Define options
set val(chan) 	Channel/WirelessChannel ;	# channel type
set val(prop) 	Propagation/TwoRayGround ;	# radio-propagation model
set val(netif) 	Phy/WirelessPhy ;		# network interface type
set val(mac) 	Mac/802_11 ;			# MAC type
set val(ifq) 	Queue/DropTail/PriQueue ;	# interface queue type
set val(ll) 	LL ;				# link layer type
set val(ant) 	Antenna/OmniAntenna ;		# antenna model
set val(ifqlen) 50 ;				# max packet in ifq
set val(nn) 	15 ;				# number of mobilenodes
set val(rp) 	DSR ;				# routing protocol
set val(x) 	500 ;				# X dimension of topography
set val(y) 	500 ;				# Y dimension of topography
set val(stop) 	10.0 ;				# time of simulation end

# Simulator Instance Creation
set ns [new Simulator]

#Creating nam and trace file:
set tracefd       [open dsr.tr w]
set namtrace      [open dsr.nam w]   

$ns trace-all $tracefd
$ns namtrace-all-wireless $namtrace $val(x) $val(y)

# set up topography object
set topo [new Topography]
$topo load_flatgrid $val(x) $val(y)

# general operational descriptor- storing the hop details in the network
create-god $val(nn)

# configure the nodes
$ns node-config -adhocRouting $val(rp) \
-llType $val(ll) \
-macType $val(mac) \
-ifqType $val(ifq) \
-ifqLen $val(ifqlen) \
-antType $val(ant) \
-propType $val(prop) \
-phyType $val(netif) \
-channelType $val(chan) \
-topoInstance $topo \
-agentTrace ON \
-routerTrace ON \
-macTrace OFF \
-movementTrace ON

# Node Creation

for {set i 0} {$i < 15} {incr i} {

set node_($i) [$ns node]
$node_($i) color black

}


for {set i 0} {$i < $val(nn)} { incr i } {
# 30 defines the node size for nam
$ns initial_node_pos $node_($i) 30
}

for {set i 0} {$i < 3 } { incr i } {
		  set bb [expr $i*10]
		  set cc [expr $i*60]
                  $node_($i) set X_ $bb
                  $node_($i) set Y_ $cc
		  #$node_($i) random-motion 0
                  
            }

for {set i 5} {$i < 10 } { incr i } {
		  set bb [expr $i*60]
		  set cc [expr ($i-5)*60]
                  $node_($i) set X_ $bb
                  $node_($i) set Y_ $cc
		  #$node_($i) random-motion 0
                  
            }

for {set i 10} {$i < 12 } { incr i } {
		  set bb [expr ($i-3)*60]
		  set cc [expr ($i-10)*60]
                  $node_($i) set X_ $bb
                  $node_($i) set Y_ $cc
		  #$node_($i) random-motion 0
                  
            }

for {set i 13} {$i < 15 } { incr i } {
		  set bb [expr ($i-2)*25]
		  set cc [expr ($i-10)*60]
                  $node_($i) set X_ $bb
                  $node_($i) set Y_ $cc
		  #$node_($i) random-motion 0
                  
            }

for {set i 3} {$i < 5 } { incr i } {
		  set bb [expr $i]
		  set cc [expr ($i+1)*60]
                  $node_($i) set X_ $bb
                  $node_($i) set Y_ $cc
		  #$node_($i) random-motion 0
                  
            }

$node_(12) set X_ 150
$node_(12) set Y_ 80

$ns at 4.5 "malicious_find"
proc malicious_find {} {
	global node_
		    $node_(5) label "sybil attacker_found"
		    $node_(1) color red
		    $node_(1) label "sybil attacker node"
		    $node_(3) color red
		    $node_(3) label "sybil attacker node"
		    $node_(13) color red
		    $node_(13) label "sybil attacker node"
		    $node_(7) color red
		    $node_(7) label "sybil attacker node"
		    $node_(9) color red
		    $node_(9) label "sybil attacker node"
		    #$ns at 6.0 "$node_($b) color red"
		    #$ns at 6.0 
}

$ns at 0.1 "source_find"
proc source_find {} {
	global node_
	$node_(5) color green
	$node_(5) label "SOURCE"
}

$ns at 1.0 "ack_request"
proc ack_request {} {
	global node_
	$node_(5) label "ACK requested"
}
	
$ns at 2.0 "ack_receive"
proc ack_receive {} {
	global node_
	$node_(5) label "ACK received"
}

$ns at 3.0 "ack_receive"
proc ack_receive {} {
	global node_
	$node_(5) label "finding_destination"
}

$ns at 4.0 "destination"
proc ack_receive {} {
	global node_
	$node_(5) label "destination_found"
	$node_(11) label "DESTINATION"
	$node_(11) color blue
}

$ns at 5.0 "data_send_receive"
proc data_send_receive {} {
	global node_
	$node_(5) label "data_sending"
	$node_(11) label "data_receiving"
}


$ns at 6.0 "trying_to_connect"
proc trying_to_connect {} {
	global node_
		    $node_(1) color darkmagenta
		    $node_(1) label "fake_request"
		    $node_(3) color darkmagenta
		    $node_(3) label "fake_request"
		    $node_(13) color darkmagenta
		    $node_(13) label "fake_request"
		    $node_(7) color darkmagenta
		    $node_(7) label "fake_request"
		    $node_(9) color darkmagenta
		    $node_(9) label "fake_request"
		    #$node_($b) label "trying_to_connect"
		    #$ns at 6.0 "$node_($b) color red"
		    #$ns at 6.0 
}


$ns at 7.0 "ARMKEY_send"
proc ARMKEY_send {} {
	global node_
	$node_(5) label "GAN_applied"
	$node_(11) label "attack_mitigated"
}


$ns at 9.5 "data_transferred"
proc data_transferred {} {
	global node_
	$node_(5) label "data_sent"
	$node_(11) label "data_received"
}

# dynamic destination setting procedure..
$ns at 0.0 "destination"
proc destination {} {
      global ns val node_
      set time 1.0
      set now [$ns now]
      for {set i 0} {$i<$val(nn)} {incr i} {
            set xx [expr rand()*500]
            set yy [expr rand()*400]
            $ns at $now "$node_($i) setdest $xx $yy 12.0"
      }
      $ns at [expr $now+$time] "destination"
}

#******************************Defining Communication Between node0 and all nodes ****************************

#Setup a TCP connection
# Defining a transport agent for sending
set tcp [new Agent/TCP]
#set udp [new Agent/UDP]

$tcp set class_ 2
# Attaching transport agent to sender node
$ns attach-agent $node_(5) $tcp
#$ns attach-agent $node_($i) $udp

# Defining a transport agent for receiving
set sink [new Agent/TCPSink]
#set null [new Agent/Null]

# Attaching transport agent to receiver node
$ns attach-agent $node_(11) $sink
#$ns attach-agent $node_(0) $null

#Connecting sending and receiving transport agents
$ns connect $tcp $sink
#$ns connect $udp $null

$tcp set fid_ 1

#Setup a FTP over TCP connection
set ftp [new Application/FTP]
$ftp attach-agent $tcp
$ftp set type_ FTP

#Defining Application instance
#set cbr [new Application/Traffic/CBR]

# Attaching transport agent to application agent
#$cbr attach-agent $udp

#Packet size in bytes and interval in seconds definition
#$cbr set packetSize_ 512
#$cbr set interval_ 0.1

# data packet generation starting time
#$ns at 1.0 "$cbr start"
$ns at 5.0 "$ftp start"




$ns at 1.0 "$ns trace-annotate \"ack_request send\""
$ns at 2.0 "$ns trace-annotate \"ack_ request receiver \""
$ns at 3.0 "$ns trace-annotate \"finding_destination\""
$ns at 4.0 "$ns trace-annotate \"Destination found\""
$ns at 5.0 "$ns trace-annotate \"Data send receive\""
$ns at 6.0 "$ns trace-annotate \"trying to connect the nodes\""
$ns at 6.1 "$ns trace-annotate \"sybil attacker nodes were found as n1 n3 n5 n7 n9 n13\""
$ns at 7.0 "$ns trace-annotate \" GAN key send #5678966789JHG6\""
$ns at 8.8 "$ns trace-annotate \"GAN key received applied #5678966789JHG6 to transfer between in source to destination\""
$ns at 9.5 "$ns trace-annotate \" Data_received\""



# data packet generation ending time
#$ns at 6.0 "$cbr stop"
#$ns at 6.0 "$ftp stop"



#stop procedure..
$ns at $val(stop) "stop"
proc stop {} {
    global ns tracefd namtrace
    $ns flush-trace
    close $tracefd
    close $namtrace
exec nam dsr.nam &
}

$ns run

 

