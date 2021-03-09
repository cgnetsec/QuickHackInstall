#!/bin/bash -i
# inspired by https://github.com/TheCrysp/Hackbuntu
# this has been tested on the following operating systems:
# Ubuntu, CentOS, Archlinux
# this is still in the testing process. Once all machines have been tested I will release a final version.
#
# by ser3n1ty
# reach out to me on twitter: @ser3n1ty
#

identify1(){
	sudo cat /etc/os-release | grep "^NAME*" | cut -d '"' -f 2;
}

checkopsys(){
	declare -a AptArray=("Kubuntu" "Xubuntu" "Lubuntu" "Parrot" "Debian" "Mint" "Knoppix" "Deepin" "Ubuntu")
	declare -a PacArray=("Arch" "ArchBang" "ArchLabs" "ArkOS" "Manjaro" "Endeavour")
	declare -a YumArray=("RedHat" "Fedora" "CentOS Linux" "SUSE" "OpenSUSE")
	
	i=0
	while true; do
		if [[ $(identify1) == ${AptArray[$i]} ]]; then
			echo "APT"
			break 2
		elif [[ $(identify1) == ${PacArray[$i]} ]]; then
			echo "PAC"
			break 2
		elif [[ $(identify1) == ${YumArray[$i]} ]]; then
			echo "YUM"
			break 2
		elif [[ ${AptArray[$i]} == "" && ${PacArray[$i]} == "" && ${YumArray[$i]} == "" ]]; then
			echo "Sorry, I cannot identify your OS. Exiting Script..."
			exit 0
		fi
		let "i=i+1"
	done
}

packageman="$(checkopsys)"

updateopsys(){
	if [[ $packageman == "APT" ]]; then
		sudo apt update -y
		sudo apt upgrade -y
	elif [[ $packageman == "PAC" ]]; then
		sudo pacman -Syyu
	elif [[ $packageman == "YUM" ]]; then
		sudo yum update -y
		sudo yum upgrade -y
	fi
}

setpm(){
	if [[ $packageman == "APT" ]]; then
		echo "sudo apt install -y "
	elif [[ $packageman == "PAC" ]]; then
		echo "sudo pacman -Syyu "
	elif [[ $packageman == "YUM" ]]; then
		echo "sudo yum install -y"
	fi
}

pm=$(setpm)

install_basic(){
	echo "installing necessary tools";
	$pm wget \
	    curl \
	    make \
	    gcc  \
	    git  \
	    unzip
	echo "done";
}

install_osspec(){
        echo "installing tools based on your package manager";
        if [[ $packageman == "APT" ]]; then
                sudo apt install -y smbclient      \
                		    dnsutils       \
               			    wireshark      \
                	            default-jdk    \
				    openssh-client \
                		    python3-pip    \
	       			    python-pip    
        elif [[ $packageman == "PAC" ]]; then
                sudo pacman -Syyu smbclient       \
                		  bind            \
                                  wireshark-qt    \
			          wireshark-cli   \
                                  jdk-openjdk     \
				  openssh-client  \
                                  python-pip      \ 
			          python2-pip
        elif [[ $packageman == "YUM" ]]; then
		sudo yum install -y https://extras.getpagespeed.com/release-el8-latest.rpm
                sudo yum install -y samba-common-tools    \
			            samba-client          \
				    bind                  \
               			    wireshark             \
				    java-11-openjdk-devel \ 
				    openssh               \
                		    python3-pip           \
		                    python2-pip
        fi
        echo "done";
}

install_tools(){
	echo "installing additional tools";
        $pm nmap           \
	    nc             \
	    vim            \
	    gdb            
	echo "done";
}
install_pr(){
	echo "installing programming languages";
	$pm python3 \
	    python  \
	    clang   \ 
	    perl    \
	    ruby    
	echo "done";
}

install_pymods(){
        echo "installing some python modules";
        pip install crackmapexec
        pip install impacket
        pip install pwntools
        pip install pyyaml
        pip install ldap3
        echo "done";
}

install_rust(){
	echo "installing rust";
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
	echo "done";
}

install_go(){
	echo "installing go";
	wget https://golang.org/dl/go1.16.linux-amd64.tar.gz; tar -xzvf go1*; sudo mv go /usr/local; rm go1*;
	printf "export GOPATH=\$HOME/go\nexport GOROOT=/usr/local/go\nexport PATH=/usr/local/sbin/:\$GOPATH/bin:\$GOROOT/bin:\$PATH\n" >> ~/.bashrc;
	export GOPATH=$HOME/go;
	export GOROOT=/usr/local/go;
	export PATH=/usr/local/sbin:$GOPATH/bin:$GOROOT/bin:$PATH;
	echo "done";
}

install_nikto(){
	echo "installing nikto";
	cd /opt/
	sudo git clone https://github.com/sullo/nikto
	cd /opt/nikto/program
	sudo ln -sfv /opt/nikto/program/nikto.pl /usr/local/bin/nikto
}

install_hydra(){
	echo "installing hydra";
	cd /opt/
	sudo git clone https://github.com/vanhauser-thc/thc-hydra
	cd /opt/thc-hydra
	sudo ./configure
	sudo make
	sudo make install
	cd .. 
	sudo rm -rf thc-hydra/
}

install_john(){
	cd /opt/
	sudo git clone https://github.com/openwall/john
	cd /opt/john/run
	sudo ln -sfv /opt/john/run/john /usr/local/bin/john
}

install_sqlmap(){
	sudo pip3 install sqlmap
}

install_masscan(){
	echo "installing masscan";
	cd /opt/
	git clone https://github.com/robertdavidgraham/masscan
	cd masscan
	sudo make
	sudo make install
	cd ..
	sudo rm -rf masscan/
	echo "done";
}

install_pwncat(){
	echo "installing pwncat";
	pip install git+https://github.com/calebstewart/pwncat.git
	echo "done";
}

install_peass(){
	echo "installing privilege escalation scripts suite";
	git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git
	sudo mv privilege-escalation-awesome-scripts-suite/ /opt/
	echo "done";
}

install_seclists(){
	echo "installing seclists";
	git clone https://github.com/danielmiessler/SecLists.git
	sudo mv SecLists/ /opt/
	echo "done";
}

install_gef(){
	echo "installing gef"
	bash -c "$(wget -q -O- https://github.com/hugsy/gef/raw/master/scripts/gef.sh | sh)"
	echo "done";
}

install_wpscan(){
	echo "installing wpscan";
	sudo gem install wpscan
	echo "done";
}

install_ffuf(){
	echo "installing ffuf";
	go get -u github.com/ffuf/ffuf
	echo "done";
}

install_gobuster(){
	echo "installing gobuster";
	go install github.com/OJ/gobuster/v3@latest
	echo "done";
}

install_amass(){
	echo "installing amass";
	go get -v github.com/OWASP/Amass/cmd/amass
	echo "done";
}

install_mimikatz(){
        echo "installing mimikatz";
        cd /opt/
        sudo wget https://github.com/gentilkiwi/mimikatz/releases/download/2.2.0-20200918-fix/mimikatz_trunk.zip
        sudo unzip mimikatz_trunk.zip
        echo "done";
}

install_sublist3r(){
	echo "installing sublist3r";
	cd/opt/
	sudo git clone https://github.com/aboul3la/Sublist3r.git
	pip3 install -r /opt/Sublist3r/requirements.txt
	sudo ln -sfv /opt/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
	echo "done";
}

install_enum4linux(){
	echo "installing enum4linux";
	cd /opt/
	sudo git clone https://github.com/CiscoCXSecurity/enum4linux
	sudo ln -sfv /opt/enum4linux/enum4linux.pl /usr/local/bin/enum4linux
	echo "done";
}
install_enum4linux-ng(){
	echo "installing enum4linux-ng";
	cd /opt/
	sudo git clone https://github.com/cddmp/enum4linux-ng
	sudo ln -sfv /opt/enum4linux-ng/enum4linux-ng.py /usr/local/bin/enum4linux-ng
	echo "done";
}

install_ghidra(){
        echo "installing ghidra";
        cd /opt/
        sudo wget https://ghidra-sre.org/ghidra_9.2.2_PUBLIC_20201229.zip
        sudo unzip ghidra_9.2.2_PUBLIC_20201229.zip
        sudo ln -sfv /opt/ghidra_9.2.2_PUBLIC_20201229/ghidraRun /usr/local/bin/ghidra
        echo "done";
}

install_metasploit(){
        echo "installing metasploit";
        cd /opt/
	curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall
        echo "done";
}

install_searchsploit(){
        echo "installing exploitdb";
        cd /opt/
        sudo git clone https://github.com/offensive-security/exploitdb.git
        sudo ln -svf /opt/exploitdb/searchsploit /usr/local/bin/searchsploit
        sudo cp -n /opt/exploitdb/.searchsploit_rc ~/
        echo "done";
}

main(){
	checkopsys
	updateopsys
	setpm
	install_basic
	install_osspec
	install_tools
	install_pr
	install_pymods
	install_rust
	install_go
	install_nikto
	install_hydra
	install_john
	install_sqlmap
	install_masscan
	install_pwncat
	install_peass
	install_seclists
	install_gef
	install_wpscan
	install_ffuf
	install_gobuster
	install_amass
	install_mimikatz
	install_sublist3r
	install_enum4linux
	install_enum4linux-ng
	install_ghidra
	install_metasploit
	install_searchsploit
}

main
