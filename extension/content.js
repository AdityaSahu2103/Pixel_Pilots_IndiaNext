// content.js - Injected into every page
// Extracts text content and URLs from the active tab

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "extract_content") {
    
    // Attempt to extract meaningful text, ignoring scripts and styles
    const bodyClone = document.body.cloneNode(true);
    const scripts = bodyClone.getElementsByTagName("script");
    const styles = bodyClone.getElementsByTagName("style");
    const navs = bodyClone.getElementsByTagName("nav");
    
    // Remove noise
    while (scripts.length > 0) scripts[0].parentNode.removeChild(scripts[0]);
    while (styles.length > 0) styles[0].parentNode.removeChild(styles[0]);
    while (navs.length > 0) navs[0].parentNode.removeChild(navs[0]);
    
    // Get visible text
    let textContent = bodyClone.innerText || "";
    
    // Limit size to avoid overwhelming the API
    if (textContent.length > 15000) {
      textContent = textContent.substring(0, 15000);
    }
    
    // Get all links
    const links = Array.from(document.links).map(a => a.href).filter(href => href.startsWith('http'));
    // Deduplicate links
    const uniqueLinks = [...new Set(links)];

    sendResponse({
      url: window.location.href,
      title: document.title,
      text: textContent,
      links: uniqueLinks.slice(0, 50) // Max 50 links
    });
  }
  return true;
});
