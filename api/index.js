const { MongoClient, GridFSBucket, ObjectId } = require("mongodb")
const formidable = require("formidable")
const crypto = require("crypto")
const fs = require("fs")
const path = require("path")

const MONGO_URI = process.env.MONGO_URI
const MONGO_DB = process.env.MONGO_DB || ""
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || ""
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || ""

let clientPromise
let db
let bucket

function json(res, status, data) {
    res.statusCode = status
    res.setHeader("Content-Type", "application/json; charset=utf-8")
    res.end(JSON.stringify(data))
}

function html(res, status, content) {
    res.statusCode = status
    res.setHeader("Content-Type", "text/html; charset=utf-8")
    res.end(content)
}

function redirect(res, url) {
    res.statusCode = 302
    res.setHeader("Location", url)
    res.end()
}

function getClient() {
    if (!MONGO_URI) {
        throw new Error("MONGO_URI belum dikonfigurasi")
    }

    if (!clientPromise) {
        const client = new MongoClient(MONGO_URI)
        clientPromise = client.connect()
    }

    return clientPromise
}

async function getDatabase() {
    if (!db) {
        const client = await getClient()
        db = client.db(MONGO_DB)
        bucket = new GridFSBucket(db, {
            bucketName: "uploads"
        })

        await db.collection("links").createIndex(
            { code: 1 },
            { unique: true }
        )

        await db.collection("links").createIndex({
            createdAt: -1
        })

        await db.collection("events").createIndex({
            code: 1,
            createdAt: -1
        })
    }

    return db
}

function randomCode(length = 8) {
    const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    let output = ""

    for (let i = 0; i < length; i++) {
        output += chars[crypto.randomInt(0, chars.length)]
    }

    return output
}

function normalizeUrl(value) {
    if (!value) return ""

    let url = String(value).trim()

    if (!/^https?:\/\//i.test(url)) {
        url = "https://" + url
    }

    try {
        const parsed = new URL(url)

        if (!["http:", "https:"].includes(parsed.protocol)) {
            return ""
        }

        return parsed.toString()
    } catch {
        return ""
    }
}

function detectPlatform(url) {
    if (!url) return "custom"

    try {
        const parsed = new URL(url)
        const host = parsed.hostname.toLowerCase()

        if (
            host === "chat.whatsapp.com" ||
            host.endsWith(".chat.whatsapp.com")
        ) {
            return "whatsapp_group"
        }

        if (
            host === "whatsapp.com" &&
            parsed.pathname.startsWith("/channel/")
        ) {
            return "whatsapp_channel"
        }

        if (
            host === "wa.me" ||
            host === "api.whatsapp.com"
        ) {
            return "whatsapp_number"
        }

        if (
            host === "instagram.com" ||
            host === "www.instagram.com" ||
            host.endsWith(".instagram.com")
        ) {
            return "instagram"
        }

        if (
            host === "t.me" ||
            host === "telegram.me" ||
            host === "telegram.dog" ||
            host.endsWith(".t.me")
        ) {
            return "telegram"
        }

        if (
            host === "youtube.com" ||
            host === "www.youtube.com" ||
            host === "youtu.be" ||
            host.endsWith(".youtube.com")
        ) {
            return "youtube"
        }

        return "custom"
    } catch {
        return "custom"
    }
}

function normalizeWhatsAppNumber(value) {
    let number = String(value || "")
        .trim()
        .replace(/[^\d+]/g, "")

    if (number.startsWith("+")) {
        number = number.slice(1)
    }

    if (number.startsWith("0")) {
        number = "62" + number.slice(1)
    }

    return number.replace(/\D/g, "")
}

function parseJsonValue(value, fallback) {
    if (value === undefined || value === null || value === "") {
        return fallback
    }

    if (typeof value === "object") {
        return value
    }

    try {
        return JSON.parse(value)
    } catch {
        return fallback
    }
}

async function readBody(req) {
    return await new Promise((resolve, reject) => {
        let body = ""

        req.on("data", chunk => {
            body += chunk.toString()
        })

        req.on("end", () => {
            if (!body) {
                resolve({})
                return
            }

            try {
                resolve(JSON.parse(body))
            } catch {
                resolve({})
            }
        })

        req.on("error", reject)
    })
}

async function parseMultipart(req) {
    return await new Promise((resolve, reject) => {
        const form = formidable({
            multiples: false,
            keepExtensions: true,
            maxFileSize: 50 * 1024 * 1024
        })

        form.parse(req, (error, fields, files) => {
            if (error) {
                reject(error)
                return
            }

            const normalizedFields = {}

            for (const [key, value] of Object.entries(fields)) {
                normalizedFields[key] = Array.isArray(value)
                    ? value[0]
                    : value
            }

            resolve({
                fields: normalizedFields,
                files
            })
        })
    })
}

function getClientIp(req) {
    const cfIp = req.headers["cf-connecting-ip"]

    if (cfIp) {
        return String(cfIp).split(",")[0].trim()
    }

    const forwarded = req.headers["x-forwarded-for"]

    if (forwarded) {
        return String(forwarded).split(",")[0].trim()
    }

    return req.socket?.remoteAddress || ""
}

async function verifyTurnstile(token, req) {
    if (!TURNSTILE_SECRET_KEY) {
        return {
            success: false,
            error: "Turnstile secret belum dikonfigurasi"
        }
    }

    if (!token || typeof token !== "string") {
        return {
            success: false,
            error: "Token Turnstile tidak ditemukan"
        }
    }

    if (token.length > 2048) {
        return {
            success: false,
            error: "Token Turnstile tidak valid"
        }
    }

    const controller = new AbortController()
    const timeout = setTimeout(() => {
        controller.abort()
    }, 10000)

    try {
        const response = await fetch(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    secret: TURNSTILE_SECRET_KEY,
                    response: token,
                    remoteip: getClientIp(req)
                }),
                signal: controller.signal
            }
        )

        const result = await response.json()

        if (!response.ok) {
            return {
                success: false,
                error: "Validasi Turnstile gagal"
            }
        }

        if (!result.success) {
            return {
                success: false,
                error: "Validasi Turnstile gagal",
                codes: result["error-codes"] || []
            }
        }

        return {
            success: true,
            hostname: result.hostname || null,
            action: result.action || null
        }
    } catch {
        return {
            success: false,
            error: "Tidak dapat memvalidasi Turnstile"
        }
    } finally {
        clearTimeout(timeout)
    }
}

function cleanRequirements(value) {
    const requirements = Array.isArray(value)
        ? value
        : parseJsonValue(value, [])

    if (!Array.isArray(requirements)) {
        return []
    }

    return requirements
        .slice(0, 20)
        .map(item => {
            if (!item || typeof item !== "object") {
                return null
            }

            let url = item.url || ""

            if (
                item.platform === "whatsapp_number" &&
                item.number &&
                !url
            ) {
                const number = normalizeWhatsAppNumber(item.number)

                if (number) {
                    url = `https://wa.me/${number}`
                }
            }

            url = normalizeUrl(url)

            if (!url) {
                return null
            }

            return {
                id: crypto.randomUUID(),
                platform: String(
                    item.platform ||
                    detectPlatform(url)
                ),
                label: String(
                    item.label ||
                    "Complete Requirement"
                ).slice(0, 120),
                url
            }
        })
        .filter(Boolean)
}

async function createUnlock(req, res) {
    const contentTypeHeader = String(
        req.headers["content-type"] || ""
    ).toLowerCase()

    let fields = {}
    let files = {}

    if (contentTypeHeader.includes("multipart/form-data")) {
        const parsed = await parseMultipart(req)
        fields = parsed.fields
        files = parsed.files
    } else {
        fields = await readBody(req)
    }

    const title = String(
        fields.title ||
        "ReyCode Unlock"
    ).trim().slice(0, 150)

    const contentType = String(
        fields.contentType ||
        fields.type ||
        "url"
    ).trim().toLowerCase()

    const requirements = cleanRequirements(
        fields.requirements
    )

    if (!requirements.length) {
        return json(res, 400, {
            success: false,
            message: "Minimal harus ada satu requirement"
        })
    }

    if (!["url", "text", "file"].includes(contentType)) {
        return json(res, 400, {
            success: false,
            message: "Content type tidak valid"
        })
    }

    let destination = ""
    let textContent = ""
    let fileInfo = null

    if (contentType === "url") {
        destination = normalizeUrl(
            fields.destination ||
            fields.url ||
            ""
        )

        if (!destination) {
            return json(res, 400, {
                success: false,
                message: "URL tujuan tidak valid"
            })
        }
    }

    if (contentType === "text") {
        textContent = String(
            fields.textContent ||
            fields.text ||
            ""
        )

        if (!textContent.trim()) {
            return json(res, 400, {
                success: false,
                message: "Isi TXT tidak boleh kosong"
            })
        }

        if (textContent.length > 1000000) {
            return json(res, 400, {
                success: false,
                message: "Isi TXT terlalu besar"
            })
        }
    }

    if (contentType === "file") {
        let uploadedFile = files.file

        if (Array.isArray(uploadedFile)) {
            uploadedFile = uploadedFile[0]
        }

        if (!uploadedFile) {
            return json(res, 400, {
                success: false,
                message: "File belum dipilih"
            })
        }

        const filepath =
            uploadedFile.filepath ||
            uploadedFile.path

        if (!filepath || !fs.existsSync(filepath)) {
            return json(res, 400, {
                success: false,
                message: "File upload tidak ditemukan"
            })
        }

        const stat = fs.statSync(filepath)

        if (stat.size > 50 * 1024 * 1024) {
            return json(res, 400, {
                success: false,
                message: "Ukuran file maksimal 50 MB"
            })
        }

        const database = await getDatabase()

        fileInfo = await new Promise((resolve, reject) => {
            const filename =
                uploadedFile.originalFilename ||
                "download"

            const uploadStream = bucket.openUploadStream(
                filename,
                {
                    contentType:
                        uploadedFile.mimetype ||
                        "application/octet-stream",
                    metadata: {
                        originalName: filename
                    }
                }
            )

            const input = fs.createReadStream(filepath)

            input.on("error", reject)
            uploadStream.on("error", reject)

            uploadStream.on("finish", () => {
                resolve({
                    id: uploadStream.id,
                    filename,
                    contentType:
                        uploadedFile.mimetype ||
                        "application/octet-stream",
                    size: stat.size
                })
            })

            input.pipe(uploadStream)
        })

        try {
            fs.unlinkSync(filepath)
        } catch {}
    }

    const database = await getDatabase()

    let code = ""

    for (let i = 0; i < 10; i++) {
        const candidate = randomCode(8)

        const exists = await database.collection("links").findOne({
            code: candidate
        })

        if (!exists) {
            code = candidate
            break
        }
    }

    if (!code) {
        return json(res, 500, {
            success: false,
            message: "Gagal membuat kode unlock"
        })
    }

    const now = new Date()

    const document = {
        code,
        title,
        contentType,
        destination,
        textContent,
        file: fileInfo,
        requirements,
        clicks: 0,
        status: "active",
        createdAt: now,
        updatedAt: now
    }

    await database.collection("links").insertOne(document)

    const host =
        req.headers["x-forwarded-host"] ||
        req.headers.host

    const proto =
        req.headers["x-forwarded-proto"] ||
        "https"

    const unlockUrl =
        `${proto}://${host}/unlock/${code}`

    return json(res, 200, {
        success: true,
        message: "Unlock link berhasil dibuat",
        code,
        url: unlockUrl,
        data: {
            code,
            title,
            contentType,
            requirements,
            file: fileInfo
                ? {
                    filename: fileInfo.filename,
                    size: fileInfo.size,
                    contentType: fileInfo.contentType
                }
                : null
        }
    })
}

function escapeHtml(value) {
    return String(value || "")
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;")
}

function renderUnlockPage(document) {
    const siteKey = escapeHtml(
        TURNSTILE_SITE_KEY
    )

    const title = escapeHtml(
        document.title || "ReyCode Unlock"
    )

    const requirements = document.requirements || []

    const requirementHtml = requirements.map(
        (item, index) => {
            const label = escapeHtml(
                item.label ||
                `Requirement ${index + 1}`
            )

            const platform = escapeHtml(
                item.platform ||
                "custom"
            )

            const url = escapeHtml(
                item.url
            )

            return `
<div class="requirement locked" data-index="${index}">
    <div class="requirement-icon">
        <span>${index + 1}</span>
    </div>

    <div class="requirement-main">
        <div class="requirement-title">${label}</div>
        <div class="requirement-platform">${platform}</div>

        <div class="requirement-actions">
            <button
                class="open-btn"
                data-url="${url}"
                disabled
            >
                OPEN LINK
            </button>

            <div class="timer hidden">
                <span class="timer-value">30</span>s
            </div>

            <div class="completed hidden">
                ✓ Completed
            </div>
        </div>
    </div>
</div>
`
        }
    ).join("")

    return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title} • ReyCode Unlock</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
* {
    box-sizing: border-box;
}

html,
body {
    margin: 0;
    min-height: 100%;
    font-family: Inter, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    background: #05070a;
    color: #f5f7fa;
}

body {
    display: flex;
    justify-content: center;
    padding: 28px 16px;
}

.container {
    width: 100%;
    max-width: 680px;
}

.header {
    text-align: center;
    margin-bottom: 24px;
}

.logo {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 54px;
    height: 54px;
    border-radius: 16px;
    background: linear-gradient(135deg, #2563eb, #06b6d4);
    font-weight: 900;
    font-size: 20px;
    box-shadow: 0 15px 45px rgba(37, 99, 235, .28);
}

.brand {
    margin-top: 12px;
    font-size: 13px;
    font-weight: 800;
    letter-spacing: .16em;
    color: #94a3b8;
}

h1 {
    margin: 12px 0 8px;
    font-size: clamp(25px, 6vw, 38px);
    line-height: 1.1;
}

.subtitle {
    color: #94a3b8;
    font-size: 14px;
}

.card {
    border: 1px solid rgba(255,255,255,.08);
    background: rgba(15,23,42,.72);
    backdrop-filter: blur(18px);
    border-radius: 22px;
    padding: 18px;
    box-shadow: 0 25px 80px rgba(0,0,0,.3);
}

.security {
    margin-bottom: 16px;
    padding: 15px;
    border-radius: 16px;
    background: rgba(2,6,23,.72);
    border: 1px solid rgba(255,255,255,.07);
}

.security-title {
    font-size: 13px;
    font-weight: 800;
    margin-bottom: 10px;
}

#turnstile {
    min-height: 65px;
    display: flex;
    justify-content: center;
    align-items: center;
}

.security-status {
    margin-top: 8px;
    font-size: 12px;
    color: #94a3b8;
    text-align: center;
}

.requirements {
    display: flex;
    flex-direction: column;
    gap: 12px;
}

.requirement {
    display: flex;
    gap: 13px;
    padding: 15px;
    border-radius: 17px;
    border: 1px solid rgba(255,255,255,.07);
    background: rgba(2,6,23,.55);
    transition: .2s ease;
}

.requirement.locked {
    opacity: .52;
}

.requirement.active {
    opacity: 1;
    border-color: rgba(37,99,235,.45);
    box-shadow: 0 10px 35px rgba(37,99,235,.08);
}

.requirement.done {
    opacity: 1;
    border-color: rgba(34,197,94,.35);
}

.requirement-icon {
    width: 40px;
    height: 40px;
    flex: 0 0 40px;
    display: flex;
    align-items: center;
    justify-content: center;
    border-radius: 13px;
    background: rgba(37,99,235,.14);
    color: #60a5fa;
    font-weight: 900;
}

.requirement.done .requirement-icon {
    background: rgba(34,197,94,.14);
    color: #4ade80;
}

.requirement-main {
    flex: 1;
    min-width: 0;
}

.requirement-title {
    font-weight: 800;
    font-size: 14px;
}

.requirement-platform {
    margin-top: 3px;
    color: #64748b;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: .08em;
}

.requirement-actions {
    display: flex;
    align-items: center;
    gap: 9px;
    flex-wrap: wrap;
    margin-top: 12px;
}

.open-btn {
    border: 0;
    border-radius: 11px;
    padding: 10px 15px;
    background: #2563eb;
    color: white;
    font-size: 12px;
    font-weight: 900;
    cursor: pointer;
    transition: .2s ease;
}

.open-btn:hover:not(:disabled) {
    transform: translateY(-1px);
    background: #1d4ed8;
}

.open-btn:disabled {
    opacity: .4;
    cursor: not-allowed;
}

.timer {
    padding: 10px 14px;
    border-radius: 11px;
    background: rgba(245,158,11,.12);
    color: #fbbf24;
    font-weight: 900;
    font-size: 13px;
}

.completed {
    padding: 10px 14px;
    border-radius: 11px;
    background: rgba(34,197,94,.12);
    color: #4ade80;
    font-weight: 900;
    font-size: 13px;
}

.unlock-area {
    margin-top: 16px;
}

.unlock-btn {
    width: 100%;
    border: 0;
    border-radius: 14px;
    padding: 15px;
    background: linear-gradient(135deg,#2563eb,#06b6d4);
    color: white;
    font-weight: 900;
    font-size: 14px;
    cursor: pointer;
    opacity: .4;
}

.unlock-btn.ready {
    opacity: 1;
}

.unlock-btn:disabled {
    cursor: not-allowed;
}

.hidden {
    display: none !important;
}

.error {
    margin-top: 12px;
    padding: 12px;
    border-radius: 12px;
    background: rgba(239,68,68,.1);
    color: #fca5a5;
    font-size: 12px;
    text-align: center;
}

.footer {
    text-align: center;
    color: #475569;
    font-size: 11px;
    margin-top: 18px;
}

@media (max-width: 520px) {
    body {
        padding: 18px 12px;
    }

    .card {
        padding: 13px;
        border-radius: 18px;
    }
}
</style>
</head>
<body>
<div class="container">

    <div class="header">
        <div class="logo">R</div>
        <div class="brand">REYCODE UNLOCK</div>
        <h1>${title}</h1>
        <div class="subtitle">
            Complete the requirements to unlock your content.
        </div>
    </div>

    <div class="card">

        <div class="security">
            <div class="security-title">
                Security Verification
            </div>

            <div
                id="turnstile"
                class="cf-turnstile"
                data-sitekey="${siteKey}"
                data-theme="dark"
                data-size="flexible"
                data-callback="onTurnstileSuccess"
                data-expired-callback="onTurnstileExpired"
                data-error-callback="onTurnstileError"
            ></div>

            <div
                id="securityStatus"
                class="security-status"
            >
                Verifying...
            </div>
        </div>

        <div class="requirements">
            ${requirementHtml}
        </div>

        <div class="unlock-area">
            <button
                id="unlockBtn"
                class="unlock-btn"
                disabled
            >
                🔒 UNLOCK CONTENT
            </button>
        </div>

        <div
            id="errorBox"
            class="error hidden"
        ></div>
    </div>

    <div class="footer">
        ReyCode Unlock · Build. Code. Create.
    </div>
</div>

<script>
const REQUIREMENTS = ${JSON.stringify(
    requirements.map(item => ({
        id: item.id,
        url: item.url
    }))
)};

const CODE = ${JSON.stringify(document.code)};
const completed = new Array(REQUIREMENTS.length).fill(false);

let turnstileToken = "";
let currentTimer = null;
let currentIndex = -1;

const securityStatus =
    document.getElementById("securityStatus");

const unlockBtn =
    document.getElementById("unlockBtn");

const errorBox =
    document.getElementById("errorBox");

function showError(message) {
    errorBox.textContent = message;
    errorBox.classList.remove("hidden");
}

function clearError() {
    errorBox.textContent = "";
    errorBox.classList.add("hidden");
}

function updateUnlockButton() {
    const ready =
        turnstileToken &&
        completed.every(Boolean);

    unlockBtn.disabled = !ready;

    if (ready) {
        unlockBtn.classList.add("ready");
        unlockBtn.textContent = "🔓 UNLOCK CONTENT";
    } else {
        unlockBtn.classList.remove("ready");
        unlockBtn.textContent = "🔒 UNLOCK CONTENT";
    }
}

function activateRequirement(index) {
    const cards =
        document.querySelectorAll(".requirement");

    cards.forEach((card, i) => {
        const button =
            card.querySelector(".open-btn");

        if (i === index && !completed[i]) {
            card.classList.remove("locked");
            card.classList.add("active");
            button.disabled = !turnstileToken;
        } else if (!completed[i]) {
            card.classList.add("locked");
            card.classList.remove("active");
            button.disabled = true;
        }
    });
}

function markCompleted(index) {
    completed[index] = true;

    const card =
        document.querySelector(
            '.requirement[data-index="' + index + '"]'
        );

    if (!card) return;

    card.classList.remove("active");
    card.classList.remove("locked");
    card.classList.add("done");

    const timer =
        card.querySelector(".timer");

    const button =
        card.querySelector(".open-btn");

    const complete =
        card.querySelector(".completed");

    if (timer) {
        timer.classList.add("hidden");
    }

    if (button) {
        button.classList.add("hidden");
    }

    if (complete) {
        complete.classList.remove("hidden");
    }

    const next = completed.findIndex(
        item => !item
    );

    if (next !== -1) {
        activateRequirement(next);
    }

    updateUnlockButton();
}

function startTimer(index) {
    if (currentTimer) {
        clearInterval(currentTimer);
        currentTimer = null;
    }

    currentIndex = index;

    const card =
        document.querySelector(
            '.requirement[data-index="' + index + '"]'
        );

    if (!card) return;

    const button =
        card.querySelector(".open-btn");

    const timer =
        card.querySelector(".timer");

    const timerValue =
        card.querySelector(".timer-value");

    button.classList.add("hidden");
    timer.classList.remove("hidden");

    let seconds = 30;

    timerValue.textContent = seconds;

    currentTimer = setInterval(() => {
        seconds -= 1;

        timerValue.textContent =
            Math.max(seconds, 0);

        if (seconds <= 0) {
            clearInterval(currentTimer);
            currentTimer = null;
            markCompleted(index);
        }
    }, 1000);
}

function openRequirement(index) {
    if (!turnstileToken) {
        showError(
            "Security verification belum selesai."
        );
        return;
    }

    if (completed[index]) {
        return;
    }

    const previous =
        completed.findIndex(item => !item);

    if (previous !== index) {
        return;
    }

    clearError();

    const url =
        REQUIREMENTS[index]?.url;

    if (!url) {
        showError("URL requirement tidak tersedia.");
        return;
    }

    window.open(
        url,
        "_blank",
        "noopener,noreferrer"
    );

    startTimer(index);
}

function onTurnstileSuccess(token) {
    turnstileToken = token || "";

    securityStatus.textContent =
        "✓ Security verification berhasil";

    clearError();

    activateRequirement(
        completed.findIndex(item => !item)
    );

    updateUnlockButton();
}

function onTurnstileExpired() {
    turnstileToken = "";

    securityStatus.textContent =
        "Verification expired. Refreshing...";

    const index =
        completed.findIndex(item => !item);

    if (index !== -1) {
        activateRequirement(index);
    }

    updateUnlockButton();

    if (window.turnstile) {
        window.turnstile.reset();
    }
}

function onTurnstileError() {
    turnstileToken = "";

    securityStatus.textContent =
        "Verification failed. Please retry.";

    updateUnlockButton();
}

document
    .querySelectorAll(".open-btn")
    .forEach((button, index) => {
        button.addEventListener(
            "click",
            () => openRequirement(index)
        );
    });

unlockBtn.addEventListener("click", async () => {
    if (!turnstileToken) {
        showError(
            "Security verification belum selesai."
        );
        return;
    }

    if (!completed.every(Boolean)) {
        return;
    }

    unlockBtn.disabled = true;
    unlockBtn.textContent = "Unlocking...";

    try {
        const response = await fetch(
            "/api/index?action=unlock-content",
            {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify({
                    code: CODE,
                    turnstileToken
                })
            }
        );

        const result =
            await response.json();

        if (!response.ok || !result.success) {
            throw new Error(
                result.message ||
                "Gagal membuka content"
            );
        }

        if (result.type === "redirect") {
            window.location.href =
                result.url;
            return;
        }

        if (result.type === "text") {
            document.open();
            document.write(
                result.html
            );
            document.close();
            return;
        }

        if (result.type === "file") {
            window.location.href =
                result.url;
            return;
        }

        throw new Error(
            "Response content tidak valid"
        );
    } catch (error) {
        unlockBtn.disabled = false;
        updateUnlockButton();

        showError(
            error.message ||
            "Gagal membuka content"
        );
    }
});

window.onTurnstileSuccess =
    onTurnstileSuccess;

window.onTurnstileExpired =
    onTurnstileExpired;

window.onTurnstileError =
    onTurnstileError;

setTimeout(() => {
    if (!turnstileToken) {
        securityStatus.textContent =
            "Menunggu verifikasi keamanan...";
    }
}, 1200);
</script>
</body>
</html>`
}

async function renderUnlock(req, res, code) {
    const database = await getDatabase()

    const document = await database.collection("links").findOne({
        code,
        status: "active"
    })

    if (!document) {
        return html(
            res,
            404,
            `<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Not Found</title>
<style>
body{margin:0;background:#05070a;color:#fff;font-family:system-ui;display:grid;place-items:center;min-height:100vh}
div{text-align:center;padding:30px}
</style>
</head>
<body>
<div>
<h1>Link tidak ditemukan</h1>
<p>Unlock link ini tidak tersedia atau sudah tidak aktif.</p>
</div>
</body>
</html>`
        )
    }

    await database.collection("links").updateOne(
        { _id: document._id },
        {
            $inc: {
                clicks: 1
            },
            $set: {
                updatedAt: new Date()
            }
        }
    )

    await database.collection("events").insertOne({
        code,
        type: "view",
        ip: getClientIp(req),
        userAgent: req.headers["user-agent"] || "",
        createdAt: new Date()
    })

    return html(
        res,
        200,
        renderUnlockPage(document)
    )
}

async function unlockContent(req, res) {
    const body = await readBody(req)

    const code = String(
        body.code || ""
    ).trim()

    const turnstileToken = String(
        body.turnstileToken || ""
    ).trim()

    if (!code) {
        return json(res, 400, {
            success: false,
            message: "Code tidak ditemukan"
        })
    }

    const verification =
        await verifyTurnstile(
            turnstileToken,
            req
        )

    if (!verification.success) {
        return json(res, 403, {
            success: false,
            message: "Security verification gagal"
        })
    }

    const database = await getDatabase()

    const document =
        await database.collection("links").findOne({
            code,
            status: "active"
        })

    if (!document) {
        return json(res, 404, {
            success: false,
            message: "Unlock link tidak ditemukan"
        })
    }

    await database.collection("events").insertOne({
        code,
        type: "unlock",
        ip: getClientIp(req),
        userAgent: req.headers["user-agent"] || "",
        createdAt: new Date()
    })

    if (document.contentType === "url") {
        return json(res, 200, {
            success: true,
            type: "redirect",
            url: document.destination
        })
    }

    if (document.contentType === "text") {
        return json(res, 200, {
            success: true,
            type: "text",
            html: renderTextContent(
                document.textContent || ""
            )
        })
    }

    if (
        document.contentType === "file" &&
        document.file?.id
    ) {
        return json(res, 200, {
            success: true,
            type: "file",
            url:
                `/api/index?action=file&id=${encodeURIComponent(
                    String(document.file.id)
                )}`
        })
    }

    return json(res, 400, {
        success: false,
        message: "Content tidak tersedia"
    })
}

function renderTextContent(text) {
    return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>ReyCode Unlock</title>
<style>
body{
    margin:0;
    padding:20px;
    background:#05070a;
    color:#f8fafc;
    font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
}
.container{
    max-width:800px;
    margin:auto;
}
.card{
    background:#0f172a;
    border:1px solid rgba(255,255,255,.08);
    border-radius:20px;
    padding:22px;
    box-shadow:0 25px 80px rgba(0,0,0,.35);
}
pre{
    white-space:pre-wrap;
    word-break:break-word;
    line-height:1.7;
    font-family:inherit;
    color:#cbd5e1;
}
.brand{
    color:#60a5fa;
    font-weight:900;
    margin-bottom:15px;
}
</style>
</head>
<body>
<div class="container">
<div class="card">
<div class="brand">REYCODE UNLOCK</div>
<pre>${escapeHtml(text)}</pre>
</div>
</div>
</body>
</html>`
}

async function downloadFile(req, res, id) {
    if (!id || !ObjectId.isValid(id)) {
        return json(res, 400, {
            success: false,
            message: "File ID tidak valid"
        })
    }

    const database = await getDatabase()

    const fileId = new ObjectId(id)

    const files = await database
        .collection("uploads.files")
        .find({
            _id: fileId
        })
        .limit(1)
        .toArray()

    if (!files.length) {
        return json(res, 404, {
            success: false,
            message: "File tidak ditemukan"
        })
    }

    const file = files[0]

    res.statusCode = 200
    res.setHeader(
        "Content-Type",
        file.contentType ||
        "application/octet-stream"
    )

    res.setHeader(
        "Content-Disposition",
        `attachment; filename="${String(
            file.filename || "download"
        ).replace(/"/g, "")}"`
    )

    if (file.length !== undefined) {
        res.setHeader(
            "Content-Length",
            String(file.length)
        )
    }

    const stream =
        bucket.openDownloadStream(fileId)

    stream.on("error", () => {
        if (!res.headersSent) {
            json(res, 500, {
                success: false,
                message: "Gagal membaca file"
            })
        } else {
            res.end()
        }
    })

    stream.pipe(res)
}

async function getStats(req, res, code) {
    if (!code) {
        return json(res, 400, {
            success: false,
            message: "Code tidak ditemukan"
        })
    }

    const database = await getDatabase()

    const document =
        await database.collection("links").findOne(
            { code },
            {
                projection: {
                    _id: 0,
                    code: 1,
                    title: 1,
                    contentType: 1,
                    requirements: 1,
                    clicks: 1,
                    status: 1,
                    createdAt: 1,
                    updatedAt: 1
                }
            }
        )

    if (!document) {
        return json(res, 404, {
            success: false,
            message: "Link tidak ditemukan"
        })
    }

    const views =
        await database.collection("events").countDocuments({
            code,
            type: "view"
        })

    const unlocks =
        await database.collection("events").countDocuments({
            code,
            type: "unlock"
        })

    return json(res, 200, {
        success: true,
        data: {
            ...document,
            views,
            unlocks
        }
    })
}

async function health(req, res) {
    try {
        const database = await getDatabase()

        await database.command({
            ping: 1
        })

        return json(res, 200, {
            success: true,
            status: "ok",
            mongodb: "connected",
            turnstile: Boolean(
                TURNSTILE_SITE_KEY &&
                TURNSTILE_SECRET_KEY
            ),
            timestamp: new Date().toISOString()
        })
    } catch (error) {
        return json(res, 500, {
            success: false,
            status: "error",
            message: error.message
        })
    }
}

module.exports = async function handler(req, res) {
    try {
        const url = new URL(
            req.url,
            `https://${req.headers.host || "localhost"}`
        )

        const action =
            url.searchParams.get("action") || ""

        if (
            action === "health" &&
            req.method === "GET"
        ) {
            return health(req, res)
        }

        if (
            action === "create" &&
            ["POST", "PUT", "PATCH"].includes(req.method)
        ) {
            return createUnlock(req, res)
        }

        if (
            action === "unlock" &&
            req.method === "GET"
        ) {
            const code =
                url.searchParams.get("code") || ""

            return renderUnlock(
                req,
                res,
                code
            )
        }

        if (
            action === "unlock-content" &&
            req.method === "POST"
        ) {
            return unlockContent(req, res)
        }

        if (
            action === "file" &&
            req.method === "GET"
        ) {
            const id =
                url.searchParams.get("id") || ""

            return downloadFile(
                req,
                res,
                id
            )
        }

        if (
            action === "stats" &&
            req.method === "GET"
        ) {
            const code =
                url.searchParams.get("code") || ""

            return getStats(
                req,
                res,
                code
            )
        }

        return json(res, 404, {
            success: false,
            message: "API route tidak ditemukan"
        })
    } catch (error) {
        console.error(error)

        return json(res, 500, {
            success: false,
            message: error.message ||
                "Internal server error"
        })
    }
}
