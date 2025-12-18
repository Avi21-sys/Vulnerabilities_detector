document.getElementById("scanBtn").addEventListener("click", () => {

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const url = tabs[0].url;

    document.getElementById("output").textContent = "Scanning...\n" + url;

    fetch("http://localhost:5000/scan", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
      document.getElementById("output").textContent =
        JSON.stringify(data, null, 2);
    })
    .catch(error => {
      document.getElementById("output").textContent =
        "Error connecting to scanner backend.";
    });

  });

});
