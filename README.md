
OpenNOP-SoloWAN

    OpenNOP-SoloWAN is an enhanced version of the Open Network Optimization 
    Platform (OpenNOP). OpenNOP-SoloWAN implements a modern dictionary based
    compression algorithm to add deduplication capabilities to OpenNOP. 

    SoloWAN is a project of the Center for Open Middleware (COM) of Universidad
    Politecnica de Madrid which aims to experiment with open-source based WAN 
    optimization solutions.

License

    OpenNOP-SoloWAN is distributed as free software under GPL version 3 
    license. See COPYING file for details on copying and usage.

    Copyright (C) 2014 OpenNOP.org (yaplej@opennop.org) for the original 
    OpenNOP code.

    Copyright (C) 2014 Center for Open Middleware (COM), Universidad 
    Politecnica de Madrid, SPAIN, for the added modules and the modifications 
    to the OpenNOP original code.

    SoloWAN:                 
        solowan@centeropenmiddleware.com
        https://github.com/centeropenmiddleware/solowan/wiki

    OpenNOP:
        http://www.opennop.org

    Center for Open Middleware (COM):
        http://www.centeropenmiddleware.com

    Universidad Politecnica de Madrid (UPM):
        http://www.upm.es   

Installation

    To install OpenNOP-SoloWAN:

    - Download code from git repository:
        git clone https://github.com/centeropenmiddleware/solowan.git

    - Install required packages:
        + For Debian/Ubuntu:
            apt-get install iptables build-essential autoconf autogen psmisc \
                            libnetfilter-queue-dev libreadline-dev
        + For RedHat/Fedora:
            yum install ...

    - Compile and install:
        cd solowan/opennopd/opennop-daemon
        ./autogen.sh 
        ./configure
        make
        make install

Manual

  OpenNOP daemon

  Usage: opennopd -h -n

  - Parameters:
      + n: Don't fork off as a daemon.
	  + h: Prints usage message.
	  + Without parameters: Opennopd runs as a Unix Daemon. The log messages are
        saved to /var/log/syslog file.

  - Configuration file. At startup OpenNOP read a configuration file located 
    in /etc/opennop/opennop.conf. The following parameters can be specified 
    in the file:
	  - optimization: Sets the optimization algorithm. 
        Values: compression, deduplication. 
        Default to: compression.
      - localid: The local IP used to add the accelerator ID into the 
        compressed packets. Mandatory parameter. Without a valid IP opennopd
        does not start.
	  - thrnum: Number of threads used for optimization. In case of using 
        deduplication, each thread uses his own dictionary. Recommended in 
        to set above 1 in case of multiple simultaneous transfers. 
        Defaults to: 1.
	  - num_pkt_cache_size: Size in number of packets of the packets cache. 
        This value should be a power of 2. In case the value is not a power 
        of 2, it is rounded to the next lower power of 2. 
        Defaults to: 131072.
      - pkt_size. Maximum size of packets in bytes. Should be aligned with 
        the maximum transmission unit (MTU). 
        Defaults to: 1500.

  OpenNOP command line client. It allows interacting with opennopd to change 
  configuration and get information from it. 

  Usage:  opennop
          opennop [command] [parameter]

  With no arguments, opennop starts in interactive (shell) mode and waits for
  the user to type commnds. With arguments, opennop executes the requested 
  command and returns the result.

  Commands:
	- compression [enable, disable]         
        -> Enable or disable compression optimization. 
	- deduplication [enable, disable]       
        -> Enable or disable deduplication optimization.
	- traces [disable]                      
        -> Disable all the traces.
	- traces [enable level]                 
        -> Set all the trace level. Level must be a number between 1 and 3. 
	- traces [enable traces_name level]     
        -> Set the trace level of "traces_name" at level. Possible values of 
           traces_name: dedup, local_update_cache, put_in_cache, recover_dedup, 
           uncomp, update_cache, update_cache_rtx. Level must be a number 
           between 1 and 3. 
	- traces [disable traces_name]
        -> Disable the traces "traces_name". Possible values of traces_name: 
           dedup, local_update_cache, put_in_cache, recover_dedup, uncomp, 
           update_cache, update_cache_rtx.
	- traces [mask] [orr and nand] [Number]
        -> Performs a logical 'orr', 'and' or 'nand' operation with the current 
           trace mask.
	- reset [stats] [in_dedup out_dedup]
        -> Reset the compressor statistics (in_dedup) or decompressor 
           statistics (out_dedup).
	- show [show_parameters]
        -> Display information sended by opennopd.
		* [show_parameters]:
			- stats in_dedup: Show the compressor statistics.
			- stats out_dedup: Show the decompressor statistics.
			- version: Show the version of the opennop.
			- compression: Show if the compression is enabled or disabled.
			- deduplication: Show if the deduplication is enabled or disabled.
			- workers: Show the statistics of the workers.
			- fetcher:Show the statistics of the fetcher.
			- sessions: Show the statistics of the sessions established.
			- traces mask: Show the traces mask.

Traffic forwarding

  To make the traffic available to OpenNOP it has to be redirected from the 
  Linux kernel to the user-space where the daemon runs. This has been 
  implemented with a packets queue by using the libnetfilter-queue
  library.

  OpenNOP-SoloWAN has been mainly tested using iptables for the redirection
  task. iptables allows to specify a libnetfilter-queue (NFQUEUE) as the 
  destination target in order to delegate the process of network packets 
  to a userspace program. In userspace, opennopd uses libnetfilter_queue 
  to connect to queue 0 and get the traffic from kernel. 

  See below some examples of iptables commands to select the traffic 
  to be forwarded to the opennopd:

	- Redirect ALL the TCP traffic:
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP
	- Redirect only the HTTP traffic:
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --sport 80
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --dport 80
	- Redirect FTP control traffic:
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --sport 21
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --dport 21
	- Redirect a range of TCP ports:
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --sport 8000:8999
		# iptables -A FORWARD -j NFQUEUE --queue-num 0 -p TCP --dport 8000:8999

  Note: originally, OpenNOP used a kernel module to do the redirection task. 
  That module is not included in OpenNOP-SoloWAN and has not been extensively 
  tested, although no change made should prevent it from working.


