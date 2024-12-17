document.addEventListener('DOMContentLoaded', () => {
    let web3;
    let contract;
    const contractAddress = '0x6D535671966639Acc8b48352a4Fa64B28122635C'; // Replace with your contract address
    const contractABI = [
        {
            "anonymous": false,
            "inputs": [
                {
                    "indexed": false,
                    "internalType": "string",
                    "name": "cid",
                    "type": "string"
                }
            ],
            "name": "ResultStored",
            "type": "event"
        },
        {
            "inputs": [
                {
                    "internalType": "string",
                    "name": "_cid",
                    "type": "string"
                }
            ],
            "name": "storeResult",
            "outputs": [],
            "stateMutability": "nonpayable",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "index",
                    "type": "uint256"
                }
            ],
            "name": "getResult",
            "outputs": [
                {
                    "internalType": "string",
                    "name": "",
                    "type": "string"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [],
            "name": "resultCount",
            "outputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        },
        {
            "inputs": [
                {
                    "internalType": "uint256",
                    "name": "",
                    "type": "uint256"
                }
            ],
            "name": "results",
            "outputs": [
                {
                    "internalType": "string",
                    "name": "cid",
                    "type": "string"
                }
            ],
            "stateMutability": "view",
            "type": "function"
        }
    ];

    if (typeof window.ethereum !== 'undefined') {
        console.log('MetaMask is installed!');
        web3 = new Web3(window.ethereum);
    } else {
        alert('Please install MetaMask to use this feature.');
    }

    const connectButton = document.getElementById('connectButton');
    const walletAddressDiv = document.getElementById('walletAddress');

    connectButton.addEventListener('click', async () => {
        try {
            const accounts = await window.ethereum.request({ method: 'eth_requestAccounts' });
            const account = accounts[0];
            walletAddressDiv.innerHTML = `Connected`;
    
            contract = new web3.eth.Contract(contractABI, contractAddress);
            console.log('Contract initialized:', contract);
    
            // Hide the connect button after successful connection
            connectButton.style.display = 'none';
        } catch (error) {
            console.error(error);
            alert('Failed to connect MetaMask.');
        }
    });
    

    document.getElementById('uploadForm').addEventListener('submit', async function (event) {
        event.preventDefault();
        const formData = new FormData(this);
        try {
            const response = await fetch('/upload_file', {
                method: 'POST',
                body: formData
            });

            const contentType = response.headers.get('Content-Type');
            if (contentType && contentType.includes('application/json')) {
                const result = await response.json();
                if (response.ok) {
                    document.getElementById('result').innerHTML = `
                        <h2>File Uploaded Successfully</h2>
                        <p>CID: ${result.cid}</p>
                        <p>Please use this CID in the "Enter File CID" form to get predictions.</p>
                    `;
                } else {
                    document.getElementById('result').innerHTML = `
                        <h2>Error:</h2>
                        <pre>${result.error}</pre>
                    `;
                }
            } else {
                const errorText = await response.text();
                document.getElementById('result').innerHTML = `
                    <h2>Unexpected Response:</h2>
                    <pre>${errorText}</pre>
                `;
            }
        } catch (error) {
            document.getElementById('result').innerHTML = `
                <h2>Network Error:</h2>
                <pre>${error.message}</pre>
            `;
        }
    });
    document.getElementById('uploadDriver').addEventListener('submit', async function (event) {
        event.preventDefault();
        const formData = new FormData(this);
        try {
            const response = await fetch('/upload_file', {
                method: 'POST',
                body: formData
            });

            const contentType = response.headers.get('Content-Type');
            if (contentType && contentType.includes('application/json')) {
                const result = await response.json();
                if (response.ok) {
                    document.getElementById('result').innerHTML = `
                        <h2>File Uploaded Successfully</h2>
                        <p>CID: ${result.cid}</p>
                        <p>Please use this CID in the "Enter File CID" form to get predictions.</p>
                    `;
                } else {
                    document.getElementById('result').innerHTML = `
                        <h2>Error:</h2>
                        <pre>${result.error}</pre>
                    `;
                }
            } else {
                const errorText = await response.text();
                document.getElementById('result').innerHTML = `
                    <h2>Unexpected Response:</h2>
                    <pre>${errorText}</pre>
                `;
            }
        } catch (error) {
            document.getElementById('result').innerHTML = `
                <h2>Network Error:</h2>
                <pre>${error.message}</pre>
            `;
        }
    });
    document.getElementById('uploadDTC').addEventListener('submit', async function (event) {
        event.preventDefault();
        const formData = new FormData(this);
        try {
            const response = await fetch('/upload_file', {
                method: 'POST',
                body: formData
            });

            const contentType = response.headers.get('Content-Type');
            if (contentType && contentType.includes('application/json')) {
                const result = await response.json();
                if (response.ok) {
                    document.getElementById('result').innerHTML = `
                        <h2>File Uploaded Successfully</h2>
                        <p>CID: ${result.cid}</p>
                        <p>Please use this CID in the "Enter File CID" form to get predictions.</p>
                    `;
                } else {
                    document.getElementById('result').innerHTML = `
                        <h2>Error:</h2>
                        <pre>${result.error}</pre>
                    `;
                }
            } else {
                const errorText = await response.text();
                document.getElementById('result').innerHTML = `
                    <h2>Unexpected Response:</h2>
                    <pre>${errorText}</pre>
                `;
            }
        } catch (error) {
            document.getElementById('result').innerHTML = `
                <h2>Network Error:</h2>
                <pre>${error.message}</pre>
            `;
        }
    });

    document.getElementById('cidForm').addEventListener('submit', async function (event) {
        event.preventDefault();
        const cid = document.getElementById('cid').value;
        try {
            const response = await fetch('/process_file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cid: cid })
            });
            const result = await response.json();
            if (response.ok) {
                console.log('Digital Signature:', result.signature);  // Log the signature to the console
                
                document.getElementById('result').innerHTML = `
                    <h2>Prediction Results:</h2>
                    <pre>${JSON.stringify(result.results, null, 2)}</pre>
                    <p>Results saved to CID: ${result.results_cid}</p>
                    <p>JSON Results saved to CID: ${result.result_json_cid}</p>
                    
                `;

                await storeResult(result.results_cid);

                const url = `https://gateway.lighthouse.storage/ipfs/${result.results_cid}`;
                generateQRCode(url);
            } else {
                document.getElementById('result').innerHTML = `
                    <h2>Error:</h2>
                    <pre>${result.error}</pre>
                `;
            }
        } catch (error) {
            document.getElementById('result').innerHTML = `
                <h2>Network Error:</h2>
                <pre>${error.message}</pre>
            `;
        }
    });

    document.getElementById('fetchResultsForm').addEventListener('submit', async function (event) {
        event.preventDefault();
        const cid = document.getElementById('fetchResultsCid').value;
        try {
            const response = await fetch(`https://gateway.lighthouse.storage/ipfs/${cid}`);
            const data = await response.json();
            if (response.ok) {
                document.getElementById('fetchedResults').innerHTML = `
                    <h2>Fetched Results:</h2>
                    <pre>${JSON.stringify(data, null, 2)}</pre>
                `;
            } else {
                document.getElementById('fetchedResults').innerHTML = `
                    <h2>Error:</h2>
                    <pre>${data.error}</pre>
                `;
            }
        } catch (error) {
            document.getElementById('fetchedResults').innerHTML = `
                <h2>Network Error:</h2>
                <pre>${error.message}</pre>
            `;
        }
    });
    document.getElementById('cidForm2').addEventListener('submit', async function (event) {
        event.preventDefault();
        const cid2 = document.getElementById('cid2').value.trim(); // Use the new ID
    
        if (!cid2) {
            document.getElementById('result').innerHTML = `
                <h2>Error:</h2>
                <pre>No CID provided</pre>
            `;
            return; // Exit if no CID
        }
    
        try {
            const response = await fetch('/alternate_file', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ cid: cid2 })
            });
    
            let result;
            try {
                result = await response.json();
            } catch (jsonError) {
                console.error('Failed to parse JSON:', jsonError);
                document.getElementById('result').innerHTML = `
                    <h2>Server Response Error:</h2>
                    <pre>${await response.text()}</pre>
                `;
                return; // Exit if JSON parsing fails
            }
    
            if (response.ok) {
                console.log('Digital Signature:', result.signature);  
                document.getElementById('result').innerHTML = `
                    <h2>Prediction Results:</h2>
                    <pre>${JSON.stringify(result.results, null, 2)}</pre>
                    <p>Results saved to CID: ${result.results_cid}</p>
                    <p>JSON Results saved to CID: ${result.result_json_cid}</p>
                `;
                await storeResult(result.results_cid);
                const url = `https://gateway.lighthouse.storage/ipfs/${result.results_cid}`;
                generateQRCode(url);
            } else {
                document.getElementById('result').innerHTML = `
                    <h2>Error:</h2>
                    <pre>${result.error}</pre>
                `;
            }
        } catch (error) {
            document.getElementById('result').innerHTML = `
                <h2>Network Error:</h2>
                <pre>${error.message}</pre>
            `;
        }
    });


    async function storeResult(cid) {
        if (contract) {
            try {
                console.log('Contract methods:', contract.methods);

                if (typeof contract.methods.storeResult !== 'function') {
                    throw new Error('storeResult function is not available in the contract.');
                }

                const accounts = await web3.eth.getAccounts();
                await contract.methods.storeResult(cid).send({ from: accounts[0] });
                alert('Result stored successfully on the blockchain.');
            } catch (error) {
                console.error('Error storing result:', error);
                alert('Failed to store result on the blockchain.');
            }
        } else {
            alert('Contract not initialized.');
        }
    }

    function generateQRCode(url) {
        const qrContainer = document.getElementById('qrCodeContainer');

        qrContainer.innerHTML = '';

        if (typeof QRCode !== 'undefined') {
            new QRCode(qrContainer, {
                text: url,
                width: 128,
                height: 128,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.H
            });
        } else {
            console.error('QRCode is not defined. Please ensure qrcode.js is loaded correctly.');
        }
    }
});
