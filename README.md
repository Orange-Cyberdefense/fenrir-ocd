                            *,ood8888booo,*
                         *,od8           8bo,*
                      *,od                   bo,*
                    *,d8                       8b,*
                   *,o                           o,    ,a8b*
                  *,8           FENRIR            8,,od8  8*
                  *8'      Valérian LEGRAND      d8'     8b*
                  *8                           d8'ba     aP'*
                  *Y,                       o8'         aP'*
                   *Y8,                      YaaaP'    ba*
                    *Y8o                   Y8'         88*
                     *`Y8               ,8"           `P*
                        *8o        ,d8P'              ba*
                  *ooood8888888P"""'                  P'*
               *,od                                  8*
            *,dP     o88o                           o'*
           *,dP          8                          8*
          *,d'   oo       8                       ,8*
          *$    d$"8      8           Y    Y  o   8*
         *d    d  d8    od  ""boooaaaaoob   d""8  8*
         *$    8  d  ood'-I   8         b  8   '8  b*
         *$   $  8  8     d  d8        `b  d    '8  b*
          *$  $ 8   b    Y  d8          8 ,P     '8  b*
          *`$$  Yb  b     8b 8b         8 8,      '8  o,*
               *`Y  b      8o  $$       d  b        b   $o*
                *8   '$     8$,,$"      $   $o      '$o$$*
                *$o$$P"                 $$o$*


# FENRIR

FENRIR is a tool designed to be used "out-of-the-box" for penetration tests and offensive engagements. Its main feature and purpose is to bypass wired 802.1x protection and to give you an access to the target network.  

**Keep in mind FENRIR is still a _Work in Progress_**

Branches : 
+ master : main branch for (relatively) stable code
+ bleeding : branch with hotfixes and latest updates

# Usage

*FENRIR must be ran as root and you must have 2 network interfaces if you want it to work*
Also, check that both network interfaces are in promisc mode and that ip_forwarding is enabled (see Install section)

To run it :
```
sudo python Interface.py
```

Notice that FENRIR's interface supports autocompletion

You can run shell commands with "!"
```
!ls -la
```

You first have to create a virtual tap for FENRIR with :
```
create_virtual_tap
```

Then you can either configure it manually or start autoconfiguration :
```
set <option> <value>
autoconf
```

Once FENRIR is configured you can run it normally or in debug mode
```
run
run_debug
```

*The wiki pages are coming shortly with examples and better explanations !*


# Troubleshooting

Are you interfaces in promisc mode ? Even FENRIR's tap interface ?  
You external interfaces must not have an IP address, only the tap hsould have one  
Your default route should be pointing to the tap interface  
Have you enabled ip_forwarding ?  
FENRIR will tell you if it is lacking configuration. It must have at least the legitimate host IP and MAC addresses.  
Not all protocols are currently supported ! But feel free to help the project by creating a module !  
If you have found a bug, report it to me ! I'll look at it as quickly as i can.


# Disclaimer

+ I suck at naming stuff & especially function names
+ The code is always a work-in-progress, there are bugs and weird stuffs ! Feel free to throw bug tickets & pull requests
+ Java sucks


# Current and planned features

*Specific protocol modules have their own separate table below !*

| Feature                          | Current state  | Details |
| :------------------------------: | :------------: | ------- |
| 802.1x tapping and bypass        | Done           | N/A |
| Stealth                          | Partially Done | Other specific headers L2/L3 are to be added |
| Autoconfiguration                | Done           | N/A |
| Reverse connections capabilities | Done           | Currently being reworked |
| Port translation                 | TODO           | Collision issue avoidance |
| Runtime interface                | Done           | N/A |
| Better stats                     | TODO           | |
| Bug smashing                     | Doing          | Bugs, bugs everywhere |
| Code cleaning                    | Doing          | It needs it badly ! |
| Not developed in Java            | Done !!!       | *'Cause we all know Java sucks right ? :)* |


# Protocol modules table

| Protocol                | Current state             | Details |
| :---------------------: | :-----------------------: | ------- |
| IP                      | Done (FENRIR Core)        | N/A |
| ARP                     | Done                      | N/A |
| ICMP                    | Done                      | N/A |
| LLMNR/NBNS (Responder)  | Partially Done            | Need to push it inside a separate module |
| SSH                     | TBD                       | Need to figure out key exchange rewritting |
| SMB                     | TBD                       | Next thing on my ToDo list ! |
| ???                     | ???                       | ??? |


# Install

+ apt-get update
+ apt-get upgrade
+ apt-get install python-pip
+ apt-get install build-essential
+ apt-get install python-dev
+ pip install python-pytun
+ pip install scapy
+ pip install Cmd2
+ git clone *this repo*

For running FENRIR 
+ sysctl net.ipv4.ip_forward=1
+ ifconfig *iface1* promisc
+ ifconfig *iface2* promisc

If you have any problem with installation, shoot me an email ! I can probably help you out !


# Have a beer and participate !

The project is open for pull requests and bug reports ! The great thing is I would be more than happy to offer you a beer for any form of contribution. Please participate in this project and help me make it better :)  
And if you don't know where to start or want some help, do not hesitate to contact me !

Also, if you want to chat about the project or ask questions, you can shoot me an email at __valerian.legrand@orange.com__ or you can also find me on IRC : __WaffleWrath__


# Docs & Vids

My presentation of 802.1x bypass techniques and FENRIR will be available shortly on the Hack in Paris website  
Link : To be added when released


# License

_This software is licensed under the terms of the MIT license_


---
*by Valérian Legrand*
