function nmap_start() { return parseInt(window.location.search.split("=")[1]) || 0; }

function display_port() {
	return document.write( parseInt(window.location.search.split("=")[1]) );
}

function nmap_prev() { 
	current = nmap_start()
	if (current > 49) {
		return current - 50
	} else {
		return 0
	}
}

function nmap_next() { return nmap_start() + 50}

function display_search() {
	searchdiv = document.getElementsByClassName("search_menu");
	if (searchdiv[0].style.display == "none") {
		searchdiv[0].style.display = "block";
	} else {
		searchdiv[0].style.display = "none";
	}
}

function fetch_os_image() {
	var os = document.getElementsByClassName("port_list");
	var os_name = os[os.length-1].getElementsByTagName("tr")[1].getElementsByTagName("td")[0].textContent;
	if (os_name.indexOf("Linux") != -1) {
		document.getElementsByClassName("ip_icon")[0].attributes[1].value = "Linux";
		return 
	}
	if (os_name.indexOf("Window") != -1) {
		document.getElementsByClassName("ip_icon")[0].attributes[1].value = "Windows";
		return 
	}
	if (os_name.indexOf("Cisco") != -1) {
		document.getElementsByClassName("ip_icon")[0].attributes[1].value = "Cisco";
		return 
	}
	if (os_name.indexOf("Linksys") != -1) {
		document.getElementsByClassName("ip_icon")[0].attributes[1].value = "Linksys";
		return 
	}
}