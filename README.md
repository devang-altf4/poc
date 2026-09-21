# Bulk PDF Digital Signing — Live Demo POC

An automated, offline-capable digital signing service demonstration for B2B tax invoices built with **FastAPI**, **pyHanko (PAdES)**, and **ReportLab**.

This POC demonstrates how enterprise systems replace manual USB token signing of 200–500 invoices with an automated backend service using a **PKCS#12 (.pfx) Document Signer Certificate**.

---

## The Core Concept

When signing a PDF document:
1. **Placeholder Allocation**: An empty placeholder is reserved inside the PDF file dictionary for `/Contents <hex>`.
2. **ByteRange Definition**: The PDF records byte boundaries in `/ByteRange [start1 len1 start2 len2]`, explicitly skipping the placeholder.
3. **Hashing**: Everything **except** the placeholder is hashed using SHA-256.
4. **Signature Insertion**: The SHA-256 digest is signed with the private key from the `.pfx` file and written into the placeholder. Inserting the signature into the reserved hole does **not** change the hash.
5. **Verification**: A verifier reads `/ByteRange`, re-hashes the exact same ranges, and verifies the signature. If even a single byte (such as the invoice total amount) is altered after signing, verification immediately fails with `Intact: False`.

---

## Quickstart (Windows)

### Prerequisites
- Python 3.10+ (Tested on Python 3.11 & 3.14)
- Powershell or Command Prompt

### 1. Installation
Clone or navigate to the repository directory:
```powershell
# Create virtual environment
python -m venv .venv

# Activate virtual environment
.\.venv\Scripts\Activate.ps1

# Install dependencies
pip install -r requirements.txt
```

*(Alternatively, if using `uv`: `uv venv .venv` and `uv pip install -r requirements.txt --python .\.venv\Scripts\python.exe`)*

### 2. Run Automated Tests
```powershell
.\.venv\Scripts\python.exe -m pytest -v tests/test_signing.py
```

### 3. Start the Web POC Server
```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --port 8000 --reload
```

Open your browser to: **[http://localhost:8000](http://localhost:8000)**

---

## 2-Minute Live Demo Script for Stakeholders

Follow these exact steps during a live meeting demonstration:

### Step 1: Certificate Inspection (20 seconds)
1. Open [http://localhost:8000](http://localhost:8000).
2. Point out **Step 1**: The active Document Signer Certificate CN is `Dream Road Technologies (TEST Document Signer)`.
3. Note the badge: `Self-Signed TEST` with KeyUsage `digitalSignature + nonRepudiation`. Explain: *“pyHanko requires non-repudiation for legal document signing. In production, we upload our CCA-licensed .pfx here.”*

### Step 2: Generate 10 Sample Tax Invoices (20 seconds)
1. Click **"Generate 10 Sample Invoices"** in **Step 2**.
2. Point out that 10 uncompressed B2B tax invoices (`INV-2026-001.pdf` through `INV-2026-010.pdf`) are generated instantly.
3. Click **"View"** on any invoice to display the professional invoice preview with GST breakdown and total amount `Rs. 59,000.00`.

### Step 3: Bulk Digital Signing (20 seconds)
1. In **Step 3**, click **"Sign All Invoices"**.
2. Point out the speed: *“10 invoices signed in ~0.5 to 1.5 seconds!”* (scales to 500+ invoices in under a minute without manual token clicks).
3. Mention the PAdES visible stamp automatically placed at the bottom-right in `Signature1`.

### Step 4: The ByteRange "Aha!" Moment (30 seconds)
1. Click **"Inspect /ByteRange"** on `INV-2026-001-signed.pdf`.
2. Scroll to the horizontal visualizer bar in **Step 4**:
   - **Range 1 (Green)**: Everything from byte 0 to the signature placeholder.
   - **Placeholder Hole (Grey)**: The reserved `<hex>` cavity.
   - **Range 2 (Green)**: Everything from the end of the placeholder to EOF.
3. Explain the caption:
   > *"Everything green was hashed and signed. The grey hole holds the signature, so inserting the signature into the file does not invalidate the file hash."*
4. Point out the exact SHA-256 digest and the first 64 hex characters of the DER CMS signature.

### Step 5: Verification & Tampering Proof (30 seconds)
1. In **Step 5**, show the **Original Signed Invoice** card:
   - **Document unchanged? ✅**: Bytes unchanged
   - **Signature genuine? ✅**: Signature maths checks out
   - **Signer trusted? ✅**: Chains to our demo root
2. Now click **"Tamper"** on `INV-2026-001-signed.pdf`.
3. Show the **Tampered Invoice Test** card:
   - The system found the plain amount `59,000.00` in the first hashed range and altered it to `99,000.00` (e.g., fraudulent invoice inflation).
   - **Document unchanged? ❌**: *Document has been altered since signing!*
   - **Signature genuine? ✅** still: the signature blob itself was not touched. It is a real signature for the *original* bytes, which no longer match.
   - Verifier caught the tampering instantly because even a 1-character alteration changes the SHA-256 hash.

---

## Deploying to Render (free tier)

The repo includes a `render.yaml`, so Render picks up every setting automatically.

1. Push this folder to a GitHub repository. The research notes and `data/` are already in `.gitignore`.
2. In Render: **New → Blueprint**, then select the repository. It creates the `bulk-signing-poc` web service:
   - build: `pip install -r requirements.txt`
   - start: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
   - Python 3.11, health check at `/healthz`
3. Optional, to keep it awake: add an **UptimeRobot** HTTP(s) monitor on `https://<your-app>.onrender.com/healthz`, every 5 minutes.

**Free-tier notes**
- Without a pinger, the service sleeps after 15 idle minutes and takes 30–60 s to wake.
- The disk is ephemeral: every restart or redeploy wipes `data/`. The TEST certificate is regenerated on startup, and invoices are one click away.
- **This is a shared demo.** Everyone with the link sees the same invoices and certificate, and *Restart Demo* clears them for everyone. The UI shows a warning banner. Do not upload a real company `.pfx` to the public instance.

---

## Adobe Acrobat Reader Trust Note

- When you open these demo-signed PDFs in **Adobe Acrobat Reader**, it may display **"Validity is UNKNOWN" (yellow question mark)**.
- **Why?** The demo certificate is self-signed and not pre-installed in Adobe's Approved Trust List (AATL) on your machine.
- **In Production**: When signing with a commercial Document Signer Certificate from a licensed Certifying Authority (e.g. eMudhra, Capricorn, Vsign, DigiCert) that is enrolled in Adobe AATL, Acrobat displays the green checkmark: **"Certified by ... all signatures are valid."**
- **Cryptographic Parity**: The underlying PKCS#7/CMS signatures, byte ranges, SHA-256 digests, and PAdES standards used by pyHanko in this POC are identical to those generated by Adobe Acrobat or enterprise signing HSMs.

---

## Technical Architecture

```
poc/
  app/
    main.py          # FastAPI application, REST endpoints, static mounting
    signing.py       # pyHanko signing, ByteRange regex parsing, verification, tampering
    certs.py         # X.509 cert generation & PKCS#12 (.pfx) management
    invoices.py      # ReportLab uncompressed B2B invoice generation
  static/
    index.html       # Single-page UI with Tailwind CSS, ByteRange visualizer
  data/              # Working directory for certificates, inputs, and outputs
  tests/
    test_signing.py  # Pytest automated test suite
  requirements.txt   # Pinned dependencies
  render.yaml        # Render blueprint (free web service, Python 3.11, /healthz)
  README.md          # Setup & demo documentation
```
