# PHPmDNS
class for mDNS querying from PHP

Note: this class is not full featured but is the beginnings of an mDNS library. At the moment it can perform A, SRV, PTR queries.

Example of scanning for chromecasts
```php
	public static function scan($wait = 15)
        {
            // Performs an mdns scan of the network to find chromecasts and returns an array
            // Let's test by finding Google Chromecasts
            $mdns = new mDNS();
            
            // Search for chromecast devices
            // For a bit more surety, send multiple search requests
            $firstresponsetime = -1;
            $lastpackettime = -1;
            $starttime = round(microtime(true) * 1000);
            $mdns->query("_googlecast._tcp.local", 1, 12, "");
            $mdns->query("_googlecast._tcp.local", 1, 12, "");
            $mdns->query("_googlecast._tcp.local", 1, 12, "");
            $cc = $wait;
    
            set_time_limit($wait * 2);
            $chromecasts = [];
            while ($cc > 0) {
                
                $inpacket = "";
                while ($inpacket == "") {
                    $inpacket = $mdns->readIncoming();
                    if ($inpacket <> "") {
                        if ($inpacket->packetheader->getQuestions() > 0) {
                            $inpacket = "";
                        }
                    }
                    
                    if ($lastpackettime <> -1) {
                        // If we get to here then we have a valid last packet time
                        $timesincelastpacket = round(microtime(true) * 1000) - $lastpackettime;
                        if ($timesincelastpacket > ($firstresponsetime * 5) && $firstresponsetime != -1) {
                            return $chromecasts;
                        }
                    }
                    
                    if ($inpacket <> "") {
                        $lastpackettime = round(microtime(true) * 1000);
                    }
                    
                    $timetohere = round(microtime(true) * 1000) - $starttime;
                    
                    // Maximum five second rule
                    if ($timetohere > 5000) {
                        return $chromecasts;
                    }
                }
                
                // If our packet has answers, then read them
                // $mdns->printPacket($inpacket);
                if ($inpacket->packetheader->getAnswerRRs() > 0) {
    
                    // $mdns->printPacket($inpacket);
                    for ($x = 0; $x < sizeof($inpacket->answerrrs); $x++) {
                        if ($inpacket->answerrrs[$x]->qtype == 12) {
                         
                            // print_r($inpacket->answerrrs[$x]);
                            if ($inpacket->answerrrs[$x]->name == "_googlecast._tcp.local") {
                                if ($firstresponsetime == -1) {
                                    $firstresponsetime = round(microtime(true) * 1000) - $starttime;
                                }
                                $name = "";
                                for ($y = 0; $y < sizeof($inpacket->answerrrs[$x]->data); $y++) {
                                    $name .= chr($inpacket->answerrrs[$x]->data[$y]);
                                }
                                // The chromecast itself fills in additional rrs. So if that's there then we have a quicker method of
                                // processing the results.
                                // First build any missing entries with any 33 packets we find.
                                for ($p = 0; $p < sizeof($inpacket->additionalrrs); $p++) {
                                    if ($inpacket->additionalrrs[$p]->qtype == 33) {
                                        $d = $inpacket->additionalrrs[$p]->data;
                                        $port = ($d[4] * 256) + $d[5];
                                        
                                        // We need the target from the data
                                        $offset = 6;
                                        $size = $d[$offset];
                                        $offset++;
                                        $target = "";
                                        for ($z = 0; $z < $size; $z++) {
                                            $target .= chr($d[$offset + $z]);
                                        }
                                        
                                        $target .= ".local";
                                        if (!isset($chromecasts[$inpacket->additionalrrs[$p]->name])) {
                                            $chromecasts[$inpacket->additionalrrs[$x]->name] = array(
                                                "port" => $port,
                                                "ip" => "",
                                                "target" => "",
                                                "friendly_name" => ""
                                            );
                                        }
                                        
                                        $chromecasts[$inpacket->additionalrrs[$x]->name]['target'] = $target;
                                    }
                                }
                                
                                // Next repeat the process for 16
                                for ($p = 0; $p < sizeof($inpacket->additionalrrs); $p++) {
                                    if ($inpacket->additionalrrs[$p]->qtype == 16) {
                                        $fn = "";
                                        for ($q = 0; $q < sizeof($inpacket->additionalrrs[$p]->data); $q++) {
                                            $fn .= chr($inpacket->additionalrrs[$p]->data[$q]);
                                        }
                                        
                                        $stp = strpos($fn, "fn=") + 3;
                                        $etp = strpos($fn, "ca=");
                                        $fn = substr($fn, $stp, $etp - $stp - 1);
                                        if (!isset($chromecasts[$inpacket->additionalrrs[$p]->name])) {
                                            $chromecasts[$inpacket->additionalrrs[$x]->name] = array(
                                                "port" => 8009,
                                                "ip" => "",
                                                "target" => "",
                                                "friendly_name" => ""
                                            );
                                        }
                                        
                                        $chromecasts[$inpacket->additionalrrs[$x]->name]['friendly_name'] = $fn;
                                    }
                                }
                                
                                // And finally repeat again for 1
                                for ($p = 0; $p < sizeof($inpacket->additionalrrs); $p++) {
                                    if ($inpacket->additionalrrs[$p]->qtype == 1) {
                                        $d = $inpacket->additionalrrs[$p]->data;
                                        $ip = $d[0] . "." . $d[1] . "." . $d[2] . "." . $d[3];
                                        
                                        foreach ($chromecasts as $key => $value) {
                                            if ($value['target'] == $inpacket->additionalrrs[$p]->name) {
                                                $value['ip'] = $ip;
                                                $chromecasts[$key] = $value;
                                            }
                                        }
                                    }
                                }
                                
                                $dontrequery = 1;
                                // Check our item. If it doesn't exist then it wasn't in the additionals, so send requests.
                                // If it does exist then check it has all the items. If not, send the requests.
                                if (isset($chromecasts[$name])) {
                                    
                                    $xx = $chromecasts[$name];
                                    if ($xx['target'] == "") {
                                        // Send a 33 request
                                        $mdns->query($name, 1, 33, "");
                                        $dontrequery = 0;
                                    }
                                    
                                    if ($xx['friendly_name'] == "") {
                                        // Send a 16 request
                                        $mdns->query($name, 1, 16, "");
                                        $dontrequery = 0;
                                    }
                                    
                                    if ($xx['target'] != "" && $xx['friendly_name'] != "" && $xx['ip'] == "") {
                                        // Only missing the ip address for the target.
                                        $mdns->query($xx['target'], 1, 1, "");
                                        $dontrequery = 0;
                                    }
                                } else {
                                    // Send queries. These'll trigger a 1 query when we have a target name.
                                    $mdns->query($name, 1, 33, "");
                                    $mdns->query($name, 1, 16, "");
                                    $dontrequery = 0;
                                }
                                
                                if ($dontrequery == 0) {
                                    $cc = $wait;
                                }
                                
                                set_time_limit($wait * 2);
                            }
                        }
                        
                        if ($inpacket->answerrrs[$x]->qtype == 33) {
                            $d = $inpacket->answerrrs[$x]->data;
                            $port = ($d[4] * 256) + $d[5];
                            
                            // We need the target from the data
                            $offset = 6;
                            $size = $d[$offset];
                            $offset++;
                            $target = "";
                            for ($z = 0; $z < $size; $z++) {
                                $target .= chr($d[$offset + $z]);
                            }
                            
                            $target .= ".local";
                            if (!isset($chromecasts[$inpacket->answerrrs[$x]->name])) {
                                $chromecasts[$inpacket->answerrrs[$x]->name] = array(
                                    "port" => $port,
                                    "ip" => "",
                                    "target" => $target,
                                    "friendly_name" => ""
                                );
                            } else {
                                $chromecasts[$inpacket->answerrrs[$x]->name]['target'] = $target;
                            }
                            
                            // We know the name and port. Send an A query for the IP address
                            $mdns->query($target, 1, 1, "");
                            $cc = $wait;
                            set_time_limit($wait * 2);
                        }
                        
                        if ($inpacket->answerrrs[$x]->qtype == 16) {
                            $fn = "";
                            for ($q = 0; $q < sizeof($inpacket->answerrrs[$x]->data); $q++) {
                                $fn .= chr($inpacket->answerrrs[$x]->data[$q]);
                            }
                            
                            $stp = strpos($fn, "fn=") + 3;
                            $etp = strpos($fn, "ca=");
                            $fn = substr($fn, $stp, $etp - $stp - 1);
                            if (!isset($chromecasts[$inpacket->answerrrs[$x]->name])) {
                                $chromecasts[$inpacket->answerrrs[$x]->name] = array(
                                    "port" => 8009,
                                    "ip" => "",
                                    "target" => "",
                                    "friendly_name" => $fn
                                );
                            } else {
                                $chromecasts[$inpacket->answerrrs[$x]->name]['friendly_name'] = $fn;
                            }
                            
                            $mdns->query($chromecasts[$inpacket->answerrrs[$x]->name]['target'], 1, 1, "");
                            $cc = $wait;
                            set_time_limit($wait * 2);
                        }
                        
                        if ($inpacket->answerrrs[$x]->qtype == 1) {
                            $d = $inpacket->answerrrs[$x]->data;
                            $ip = $d[0] . "." . $d[1] . "." . $d[2] . "." . $d[3];
                            
                            // Loop through the chromecasts and fill in the ip
                            foreach ($chromecasts as $key => $value) {
                                if ($value['target'] == $inpacket->answerrrs[$x]->name) {
                                    $value['ip'] = $ip;
                                    $chromecasts[$key] = $value;
                            
                                    // If we have an IP address but no friendly name, try and get the friendly name again!
                                    if (strlen($value['friendly_name']) < 1) {
                                        $mdns->query($key, 1, 16, "");
                                        $cc = $wait;
                                        set_time_limit($wait * 2);
                                    }
                                }
                            }
                        }
                        
                    }
                }
                $cc--;
            }
            return $chromecasts;
        }
``
