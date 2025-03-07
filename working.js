// Simulate Monitoring Data
const monitoringData = [
    { id: 1, ip: "192.168.1.1", status: "Safe" },
    { id: 2, ip: "192.168.1.100", status: "Intrusion Detected" },
    { id: 3, ip: "10.0.0.2", status: "Safe" }
];

const monitoringTable = document.getElementById("monitoringTable");

// Populate Monitoring Table
function populateTable() {
    monitoringTable.innerHTML = "";
    monitoringData.forEach((item) => {
        const row = document.createElement("tr");
        row.innerHTML = `
            <td>${item.id}</td>
            <td>${item.ip}</td>
            <td>${item.status}</td>
            <td>
                <button class="btn btn-${item.status === "Safe" ? "success" : "danger"}">
                    ${item.status === "Safe" ? "Allow" : "Block"}
                </button>
            </td>
        `;
        monitoringTable.appendChild(row);
    });
}

// Block IP Functionality
document.getElementById("blockButton").addEventListener("click", () => {
    const ipToBlock = document.getElementById("blockIp").value;
    if (ipToBlock) {
        alert(`IP Address ${ipToBlock} has been blocked!`);
        document.getElementById("blockIp").value = "";
    } else {
        alert("Please enter an IP address to block.");
    }
});

// Initialize
populateTable();

// Example: Handle Contact Form Submission
document.getElementById("contactForm").addEventListener("submit", function (event) {
    event.preventDefault();
    alert("Thank you for reaching out! We'll get back to you soon.");
});

