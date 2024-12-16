import React, { useState } from 'react';
import './App.css';
import BigInteger from 'big-integer';
import CryptoJS from 'crypto-js'; // Ensure you install this via npm


function App() {
  // State variables for key generation, signature generation, and verification
  const [p, setP] = useState('');
  const [q, setQ] = useState('');
  const [h, setH] = useState('');
  const [g, setG] = useState(null);
  const [x, setX] = useState('');
  const [y, setY] = useState(null);
  // eslint-disable-next-line
  const [message, setMessage] = useState(''); // Message from file
  const [messageHash, setMessageHash] = useState(''); // New state for file hash
  const [k, setK] = useState('');
  const [r, setR] = useState(null);
  const [s, setS] = useState(null);
  const [pError, setPError] = useState('');
  const [qError, setQError] = useState('');
  const [hError, setHError] = useState('');
  const [xError, setXError] = useState('');
  const [kError, setKError] = useState('');
  const [primeFactors, setPrimeFactors] = useState([]);
  const [sVerify, setSVerify] = useState('');
  const [qVerify, setQVerify] = useState('');
  const [w, setW] = useState(null);
  const [newR, setNewR] = useState('');
  const [newMessage, setNewMessage] = useState('');
  const [u1, setU1] = useState(null);
  const [u2, setU2] = useState(null);
  const [verificationResult, setVerificationResult] = useState('');
  const [newG, setNewG] = useState('');
  const [v, setV] = useState(null);

  // States to track time taken for signature generation and verification
  const [signatureTime, setSignatureTime] = useState(null);
  const [verificationTime, setVerificationTime] = useState(null);

  // Prime number validation
  const isPrime = (n) => {
    if (n <= 1) return false;
    for (let i = 2; i <= Math.sqrt(n); i++) {
      if (n % i === 0) return false;
    }
    return true;
  };

  // Calculating prime factors of p - 1
  const calculatePrimeFactors = (n) => {
    let factors = [];
    for (let i = 2; i <= n; i++) {
      if (n % i === 0 && isPrime(i)) {
        factors.push(i);
      }
    }
    return factors;
  };

  // Input handlers
  const handlePChange = (e) => {
    const value = parseInt(e.target.value, 10);
    setP(value);

    if (isPrime(value)) {
      setPError('');
      const factors = calculatePrimeFactors(value - 1);
      setPrimeFactors(factors);
    } else {
      setPError('p must be a prime number.');
      setPrimeFactors([]);
    }
    setQ('');
    setH('');
    setG(null);
    setY(null);
    setQError('');
    setHError('');
  };

  const handleQChange = (e) => {
    const value = parseInt(e.target.value, 10);
    setQ(value);

    if (primeFactors.length > 0 && !primeFactors.includes(value)) {
      setQError(`q must be one of the factors of p - 1: ${primeFactors.join(', ')}`);
    } else {
      setQError('');
    }
  };

  const handleHChange = (e) => {
    const value = parseInt(e.target.value, 10);
    setH(value);

    if (value <= 0 || value >= p) {
      setHError(`h must be between 1 and p - 1 (1 and ${p - 1})`);
    } else {
      setHError('');
    }
  };

  const generateG = () => {
    if (h && p && q && h > 0 && h < p && primeFactors.includes(q)) {
      const hBig = BigInteger(h);
      const exponent = BigInteger((p - 1) / q);
      const pBig = BigInteger(p);
      const gValue = hBig.modPow(exponent, pBig);
      setG(gValue.toString());
    }
  };

  const handleXChange = (e) => {
    const value = parseInt(e.target.value, 10);
    setX(value);

    if (value >= q) {
      setXError(`x (private key) must be less than q (${q})`);
    } else {
      setXError('');
    }
  };

  const generateY = () => {
    if (g && x && p && x < q) {
      const gBig = BigInteger(g);
      const xBig = BigInteger(x);
      const pBig = BigInteger(p);
      const yValue = gBig.modPow(xBig, pBig);
      setY(yValue.toString());
    }
  };

  const handleFileUpload = (e) => {
    const file = e.target.files[0];

    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const fileContent = event.target.result;
        setMessage(fileContent);

        const fileHash = CryptoJS.SHA256(fileContent).toString(CryptoJS.enc.Hex);
        setMessageHash(fileHash);
      };
      reader.readAsText(file);
    }
  };

  const handleKChange = (e) => {
    const value = parseInt(e.target.value, 10);
    setK(value);

    if (value >= q) {
      setKError(`k must be less than q (${q})`);
    } else {
      setKError('');
    }
  };

  const generateR = () => {
    if (g && k && p && q && k < q) {
      const gBig = BigInteger(g);
      const kBig = BigInteger(k);
      const pBig = BigInteger(p);
      const qBig = BigInteger(q);

      const gPowerK = gBig.modPow(kBig, pBig);
      const rValue = gPowerK.mod(qBig);
      setR(rValue.toString());
    }
  };

  // Measure time for signature generation
  const generateS = () => {
    if (r && k && q && x && messageHash) {
      const start = performance.now(); // Start time
      const qBig = BigInteger(q);
      const kBig = BigInteger(k);
      const xBig = BigInteger(x);
      const rBig = BigInteger(r);

      const hashBig = BigInteger(messageHash, 16);
      const kInv = kBig.modInv(qBig);
      const sValue = kInv.multiply(hashBig.add(xBig.multiply(rBig))).mod(qBig);
      setS(sValue.toString());

      const end = performance.now(); // End time
      setSignatureTime((end - start).toFixed(2)); // Calculate and set time
    }
  };

  const handleSVerifyChange = (e) => {
    setSVerify(e.target.value);
  };

  const handleQVerifyChange = (e) => {
    setQVerify(e.target.value);
  };

  const generateW = () => {
    if (sVerify && qVerify) {
      const sBig = BigInteger(sVerify);
      const qBig = BigInteger(qVerify);

      const wValue = sBig.modInv(qBig);
      setW(wValue.toString());
    }
  };

  const handleNewRChange = (e) => {
    setNewR(e.target.value);
  };

  // Handle file upload for verification
  const handleFileVerificationUpload = (e) => {
    const file = e.target.files[0];

    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        const fileContent = event.target.result;

        // Hash the file content for verification
        const fileHash = CryptoJS.SHA256(fileContent).toString(CryptoJS.enc.Hex);
        setNewMessage(fileHash); // Store the hash for the verification process
      };
      reader.readAsText(file);
    }
  };

  const generateU1 = () => {
    if (newMessage && w && qVerify) {
      const qBig = BigInteger(qVerify);
      const wBig = BigInteger(w);

      // The newMessage now contains the hash of the file content
      const newMessageBig = BigInteger(newMessage, 16);

      const u1Value = newMessageBig.multiply(wBig).mod(qBig);
      setU1(u1Value.toString());
    }
  };

  const generateU2 = () => {
    if (newR && w && qVerify) {
      const rBig = BigInteger(newR);
      const wBig = BigInteger(w);
      const qBig = BigInteger(qVerify);

      const u2Value = rBig.multiply(wBig).mod(qBig);
      setU2(u2Value.toString());
    }
  };

  const handleNewGChange = (e) => {
    setNewG(e.target.value);
  };

  const generateV = () => {
    if (newG && u1 && u2 && p && qVerify && newR && y) {
      const start = performance.now(); // Start time
      const gBig = BigInteger(newG);
      const u1Big = BigInteger(u1);
      const u2Big = BigInteger(u2);
      const pBig = BigInteger(p);
      const qBig = BigInteger(qVerify);
      const yBig = BigInteger(y);
      const rBig = BigInteger(newR);

      const gPowerU1 = gBig.modPow(u1Big, pBig);
      const yPowerU2 = yBig.modPow(u2Big, pBig);

      const vValue = gPowerU1.multiply(yPowerU2).mod(pBig).mod(qBig);
      setV(vValue.toString());

      const end = performance.now(); // End time
      setVerificationTime((end - start).toFixed(2)); // Calculate and set time

      if (vValue.equals(rBig)) {
        setVerificationResult('Signature is valid.');
      } else {
        setVerificationResult('Signature is invalid.');
      }
    }
  };

  return (
    <div className="App">
     

      <div className="section">
        <h2>Key Generation</h2>
        
        <label>Enter p:</label>
        <input type="number" placeholder="Enter p" value={p} onChange={handlePChange} /><br></br>
        {pError && <p className="error">{pError}</p>}
        
        <label>Enter q:</label>
        <input type="number" placeholder="Enter q" value={q} onChange={handleQChange} /><br></br>
        {qError && <p className="error">{qError}</p>}

        <label>Enter h:</label>
        <input type="number" placeholder="Enter h" value={h} onChange={handleHChange} /><br></br>
        {hError && <p className="error">{hError}</p>}
        
        <button onClick={generateG}>Generate g</button>
        {g && <p>g: {g}</p>}
        
        <label>Enter x (private key):</label>
        <input type="number" placeholder="Enter x" value={x} onChange={handleXChange} /><br></br>
        {xError && <p className="error">{xError}</p>}

        <button onClick={generateY}>Generate y (public key)</button>
        {y && <p>y: {y}</p>}
      </div>

      <div className="section">
        <h2>Signature Generation</h2>
        
        <label>UPLOAD FILE</label>
        <input type="file" onChange={handleFileUpload} /><br></br>
        {messageHash && <p>Message Hash: {messageHash}</p>}
        
        <label>Enter k:</label>
        <input type="number" placeholder="Enter k" value={k} onChange={handleKChange} /><br></br>
        {kError && <p className="error">{kError}</p>}

        <button onClick={generateR}>Generate r</button>
        {r && <p>r: {r}</p>}

        <button onClick={generateS}>Generate s</button>
        {s && <p>s: {s}</p>}
        
        {signatureTime && <p>Time taken for signature generation: {signatureTime} ms</p>}
      </div>

      <div className="section">
        <h2>Signature Verification</h2>
        
        <label>ENTER S VALUE</label>
        <input type="text" placeholder="Enter s for verification" value={sVerify} onChange={handleSVerifyChange} /><br></br>

        <label>ENTER Q VALUE</label>
        <input type="text" placeholder="Enter q for verification" value={qVerify} onChange={handleQVerifyChange} /><br></br>
        
        <button onClick={generateW}>Generate w</button>
        {w && <p>w: {w}</p>}

        <label>ENTER R VALUE</label>
        <input type="text" placeholder="Enter R for verification" value={newR} onChange={handleNewRChange} /><br></br>

        <label>UPLOAD FILE FOR VERIFICATION</label>
        <input type="file" onChange={handleFileVerificationUpload} /><br></br>

        <button onClick={generateU1}>Generate u1</button>
        {u1 && <p>u1: {u1}</p>}

        <button onClick={generateU2}>Generate u2</button>
        {u2 && <p>u2: {u2}</p>}

        <label>ENTER G VALUE</label>
        <input type="text" placeholder="Enter g for verification" value={newG} onChange={handleNewGChange} /><br></br>

        <button onClick={generateV}>Verify Signature</button>
        {v && <p>v: {v}</p>}
        
        {verificationTime && <p>Time taken for verification: {verificationTime} ms</p>}
        {verificationResult && <p>{verificationResult}</p>}
      </div>
    </div>
  );
}

export default App;
