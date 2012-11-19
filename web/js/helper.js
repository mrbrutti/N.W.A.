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