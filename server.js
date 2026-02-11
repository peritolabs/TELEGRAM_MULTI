// ===============================================
// TELEGRAM SERVER (Admin + Agent Role-Based)
// ===============================================
require("dotenv").config();

const express = require("express");
const https = require("https");
const cors = require("cors");
const { Server } = require("socket.io");
const mongoose = require("mongoose");

const { TelegramClient, Api } = require("telegram");
const { StringSession } = require("telegram/sessions");
const { NewMessage } = require("telegram/events");
const { CustomFile } = require("telegram/client/uploads");
const fs = require("fs");
const path = require("path");

const TelegramSession = require("./models/TelegramSession");
const ChatIndex = require("./models/ChatIndex");
const Message = require("./models/Message");
const NumberNameCache = require("./models/NumberNameCache");
const TenantAgent = require("./models/TenantAgent")

const { decryptMessage, encryptMessage } = require("./aes")

// -----------------------------------------------
// MongoDB
// -----------------------------------------------
mongoose
    .connect(process.env.MONGO_URL, { dbName: "TG_AICONNECT_MULTI" })
    .then(() => console.log("📦 MongoDB Bağlandı"))
    .catch((err) => console.log("MongoDB Hatası:", err));

// Express and Servers
const app = express();

// Middleware
app.use(express.json());
app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));

// SSL sertifikası dosyaları
const sslOptions = {
    key: fs.readFileSync('/etc/letsencrypt/live/tgm.aiconnect.com.tr/privkey.pem'),
    cert: fs.readFileSync('/etc/letsencrypt/live/tgm.aiconnect.com.tr/cert.pem'),
    ca: fs.readFileSync('/etc/letsencrypt/live/tgm.aiconnect.com.tr/chain.pem'),
};

const server = https.createServer(sslOptions, app); // HTTPS sunucusu oluşturuldu
const io = new Server(server, {
    cors: {
        origin: [
            'http://localhost:3000',
            'https://waclient.aiconnect.com.tr',
            'https://waserver.aiconnect.com.tr',
            'https://demo.aiconnect.com.tr',
        ], // Bağlantı kurulacak originler eklendi
        methods: ['GET', 'POST'],
        credentials: true,
        allowedHeaders: ['origin', 'X-Requested-With', 'Content-Type', 'Accept'],
    },
    pingInterval: 25000, // Ping aralığı
    pingTimeout: 20000,  // Ping zaman aşımı
    maxPayload: 100000000, // Maksimum yük boyutu
});


const apiId = Number(process.env.API_ID);
const apiHash = process.env.API_HASH;

// Tüm Telegram clientları
const tgClients = new Map(); // key = tenantId:agentId

// ====================================================
// HELPER
// ====================================================
// Artık hesaplar accountId (telefon numarası) ile yönetiliyor
function buildKey(tenantId, accountId) {
    return `${tenantId}:${accountId}`;
}

function waitForEvent(socket, event) {
    return new Promise((resolve) => socket.once(event, resolve));
}

// Yeni chatKey formatı: tenantid-telegramusername-telegramnumarası
function buildChatKey(tenantId, telegramUsername, telegramNumber) {
    return `${tenantId}-${telegramUsername}-${telegramNumber}`;
}

async function saveMessageToDB(data) {
    const m = new Message(data);
    await m.save();
    return m;
}

async function getCustomerNameFromCacheOrPacket(client, tenantId, userId, packetUser) {
    const telegramUserId = String(userId);

    // 🔹 Client (Telegram hesabı) telefonu
    const me = await client.getMe();
    const clientPhone = me.phone || "unknown";

    // 🔹 Username (yoksa userId fallback)
    const telegramUsername = packetUser?.username || telegramUserId;

    // 🔹 Display name
    const resolvedName =
        [packetUser?.firstName, packetUser?.lastName].filter(Boolean).join(" ")
        || telegramUsername
        || `TG_${telegramUserId}`;

    // ❗ CHATKEY HER ZAMAN BURADA ÜRETİLİR (CACHE’TEN ASLA OKUNMAZ)
    const chatKey = `${tenantId}-${telegramUsername}-+${clientPhone}`;

    // 🔹 Cache SADECE isim için tutulur
    await NumberNameCache.findOneAndUpdate(
        { tenantId, telegramname: telegramUserId },
        {
            tenantId,
            telegramname: telegramUserId,
            username: telegramUsername,
            name: resolvedName,
            updatedAt: new Date(),
        },
        { upsert: true }
    );

    return {
        telegramname: telegramUsername,
        name: resolvedName,
        chatKey,
        clientPhone,
    };
}


async function ensureChatIndex({
    tenantId,
    chatKey,
    telegramname,
    name,
    ownerAgentId,
    assignedAgentId,
    assignedAgentExtension,
    accountId
}) {
    const now = new Date();

    await ChatIndex.findOneAndUpdate(
        { tenantId, chatKey },
        {
            $setOnInsert: {
                tenantId,
                chatKey,
                telegramname,
                name,
                ownerAgentId,
                accountId
            },
            $set: {
                assignedAgentId,
                assignedAgentExtension,
                lastMessageAt: now,
                isActive: true,

            },
        },
        { upsert: true }
    );
}

async function buildAdminActiveChatsList(tenantId) {
    const rows = await ChatIndex.find({ tenantId, isActive: true }).sort({ lastMessageAt: -1 }).lean();

    return rows.map(r => ({
        chatKey: r.chatKey,
        telegramname: r.telegramname,
        name: r.name,
        ownerAgentId: r.ownerAgentId,
        assignedAgentId: r.assignedAgentId,
        assignedAgentExtension: r.assignedAgentExtension,
        accountId: r.accountId,
        lastMessageAt: r.lastMessageAt ? r.lastMessageAt.toISOString() : null,
    }));
}

async function buildAgentActiveChatsList(tenantId, agentId, accountId) {
    console.log("accountId -->", accountId)
    const query = {
        tenantId: String(tenantId),
        isActive: true,
        $or: [
            { ownerAgentId: String(agentId) },
            { assignedAgentId: String(agentId) },
        ],
    };
    if (accountId) {
        query.accountId = accountId;
    }
    const rows = await ChatIndex.find(query)
        .sort({ lastMessageAt: -1 })
        .lean();

    return rows.map(r => ({
        chatKey: r.chatKey,
        telegramname: r.telegramname,
        name: r.name,
        ownerAgentId: r.ownerAgentId,
        assignedAgentId: r.assignedAgentId,
        accountId: r.accountId,
        lastMessageAt: r.lastMessageAt ? r.lastMessageAt.toISOString() : null,
    }));
}

function emitActiveChatsToAdmins(tenantId, list) {
    io.sockets.sockets.forEach((socket) => {
        const q = socket.handshake.query;
        if (q.role === "admin" && q.tenantId === String(tenantId)) {
            const json = JSON.stringify(list);
            const encrypted = encryptMessage(json)
            socket.emit("active-chats", { data: encrypted });
        }
    });
}

async function emitActiveChats(tenantId, agentId = null, accountId) {
    if (agentId) {
        const list = await buildAgentActiveChatsList(tenantId, agentId, accountId);
        const json = JSON.stringify(list);
        const encrypted = encryptMessage(json)
        io.to(`agent:${tenantId}:${agentId}`).emit("active-chats", { data: encrypted });
        return;
    }
    const list = await buildAdminActiveChatsList(tenantId);
    emitActiveChatsToAdmins(tenantId, list);
}

async function buildTenantAgentsList(tenantId) {
    const rows = await TenantAgent.find({ tenantId }).lean();

    return rows.map(a => ({
        userId: a.agentId,
        role: a.role,
        extension: a.extension,
        lastSeenAt: a.updatedAt,
        userName: a.userTitle
    }));
}

async function emitTenantAgents(tenantId) {
    const list = await buildTenantAgentsList(tenantId);

    io.to(`admin:tenant:${tenantId}`).emit("tenant-agents", list);
}

async function getTelegramAccountInfo(client) {
    try {
        const me = await client.getMe();

        return {
            telegramId: me.id?.value ? String(me.id.value) : String(me.id),
            username: me.username || null,
            phone: me.phone || null,
        };
    } catch (err) {
        console.error("getTelegramAccountInfo error:", err);
        return null;
    }
}

async function sendTelegramPhotoNative(client, chatId, media) {
    // base64 → buffer
    const buffer = Buffer.from(media.data, "base64");

    // geçici dosya (Telegram uploadFile BUNU SEVİYOR)
    const tmpPath = path.join(
        "/tmp",
        `tg_${Date.now()}_${media.fileName || "photo.jpg"}`
    );

    fs.writeFileSync(tmpPath, buffer);

    try {
        const uploaded = await client.uploadFile({
            file: new CustomFile(
                path.basename(tmpPath),
                fs.statSync(tmpPath).size,
                tmpPath
            ),
            workers: 1,
        });

        return await client.invoke(
            new Api.messages.SendMedia({
                peer: chatId,
                media: new Api.InputMediaUploadedPhoto({
                    file: uploaded,
                }),
                message: media.caption || "",
                randomId: BigInt(Date.now()),
            })
        );
    } finally {
        fs.unlinkSync(tmpPath); // temizlik
    }
}


async function sendTelegramDocumentNative(client, chatId, media) {
    const buffer = Buffer.from(media.data, "base64");
    const tmpPath = path.join("/tmp", media.fileName || "file.bin");

    fs.writeFileSync(tmpPath, buffer);

    try {
        const uploaded = await client.uploadFile({
            file: new CustomFile(
                path.basename(tmpPath),
                fs.statSync(tmpPath).size,
                tmpPath
            ),
            workers: 1,
        });

        return await client.invoke(
            new Api.messages.SendMedia({
                peer: chatId,
                media: new Api.InputMediaUploadedDocument({
                    file: uploaded,
                    mimeType: media.mimetype,
                    attributes: [
                        new Api.DocumentAttributeFilename({
                            fileName: media.fileName || "file",
                        }),
                    ],
                }),
                message: media.caption || "",
                randomId: BigInt(Date.now()),
            })
        );
    } finally {
        fs.unlinkSync(tmpPath);
    }
}




// ====================================================
// SOCKET.IO ANA BAĞLANTI
// ====================================================
io.on("connection", (socket) => {
    const { role, tenantId, agentId, extension, token, userTitle } = socket.handshake.query;

    console.log("⚡ Yeni Telegram Socket:", {
        role,
        tenantId,
        agentId,
        extension,
    });

    if (!role || !tenantId || !agentId) {
        socket.emit("tg-error", "Eksik bağlantı parametreleri");
        return;
    }

    if (role === "admin") setupAdminSocket(socket, tenantId, agentId, extension, token);
    else if (role === "agent") setupAgentSocket(socket, tenantId, agentId, extension, token, userTitle, role);
    else socket.emit("tg-error", "Geçersiz rol");
});

// ====================================================
// ADMIN SOCKET EVENTLERİ
// ====================================================
async function setupAdminSocket(socket, tenantId, agentId, extension, token) {

    // Tenant'a bağlı tüm Telegram hesaplarını gönder (adminler tümünü görebilir)
    const adminSessions = await TelegramSession.find({ tenantId });
    socket.emit("active-telegram-sessions", adminSessions);

    // Admin: Telegram hesabını agentlara ata
    socket.on("assign-telegram-agents", async (payload) => {
        try {
            const { sessionId, agentIds, } = payload;
            if (!sessionId || !Array.isArray(agentIds) || agentIds.length === 0) {
                socket.emit("tg-error", "sessionId ve agentIds zorunludur");
                return;
            }

            // Sadece admin kontrolü (zaten admin socketi)
            const session = await TelegramSession.findOneAndUpdate(
                { tenantId, accountId: sessionId },
                { $set: { assignedAgents: agentIds } },
                { new: true }
            );

            if (!session) {
                socket.emit("tg-error", "Telegram hesabı bulunamadı");
                return;
            }

            // İlgili agentlara ve tüm adminlere güncel bilgiyi gönder
            io.to(`admin:tenant:${tenantId}`).emit("telegram-session-updated", session);
            agentIds.forEach(aid => {
                io.to(`agent:${tenantId}:${aid}`).emit("telegram-session-assigned", session);
            });

            socket.emit("assign-telegram-agents-success", { sessionId, agentIds });
        } catch (err) {
            socket.emit("tg-error", "Atama işlemi sırasında hata oluştu");
        }
    });

    socket.on("get-account-assignments", async (payload) => {
        try {
            const { accountId } = payload;

            if (!tenantId) {
                socket.emit("tg-error", "tenantId bulunamadı");
                return;
            }

            if (!accountId) {
                socket.emit("tg-error", "phone zorunludur");
                return;
            }

            const session = await TelegramSession.findOne({
                tenantId,
                accountId, // DB’de hangi alan varsa onu kullan
            }).lean();

            if (!session) {
                socket.emit("tg-error", "Telegram hesabı bulunamadı");
                return;
            }

            socket.emit("account-assignments", {
                accountId,
                assignedAgents: session.assignedAgents || [],
            });

        } catch (err) {
            console.error("get-account-assignments error:", err);
            socket.emit("tg-error", err?.message || "Atamalar alınamadı");
        }
    });

    console.log(`👑 ADMIN bağlandı → ${tenantId}:${agentId}`);

    socket.join(`admin:${tenantId}:${agentId}`);
    socket.join(`admin:tenant:${tenantId}`);

    // const status = await checkTelegramSessionStatus(tenantId, agentId);
    // socket.emit("tg-session-status", status);

    socket.on("tg-start", async ({ phone }) => {
        const saved = await TelegramSession.findOne({ tenantId, accountId: phone });

        if (saved?.session) return connectWithSession(tenantId, phone, saved.session, socket);

        return connectWithoutSession(tenantId, agentId, socket, extension, phone);
    });

    const list = await buildAdminActiveChatsList(tenantId)
    const json = JSON.stringify(list);
    const encrypted = encryptMessage(json)

    socket.emit("active-chats", { data: encrypted });

    socket.emit(
        "tenant-agents",
        await buildTenantAgentsList(tenantId)
    );

    socket.on("get-chat", async (payload) => {
        const decrypted = decryptMessage(payload.data);
        const parsed = JSON.parse(decrypted);
        const { chatKey, count } = parsed
        try {
            const total = await Message.countDocuments({ chatKey, isActive: true });

            const skip = Math.max(total - count, 0);

            const msgs = await Message.find({ chatKey, isActive: true })
                .sort({ timestamp: 1 })  // her zaman zaman sırasına göre
                .skip(skip)
                .limit(count);

            const payload = {
                chatKey,
                messages: msgs
            }

            const json = JSON.stringify(payload);
            const encrypted = encryptMessage(json)

            socket.emit("chat-history", { data: encrypted });
        } catch (err) {
            console.error(err);
        }
    });

    // Admin mesaj gönderebilir
    socket.on("send-message", (payload) =>
        handleSendMessage(socket, tenantId, agentId, payload, role = "admin", extension)
    );

    socket.on("delete-chat", async (payload) => {
        const decrypted = decryptMessage(payload.data);
        const parsed = JSON.parse(decrypted);
        const { chatKey } = parsed;
        if (!chatKey) return;

        // 🔍 Sohbeti bul (agent bilgisi için)
        const chat = await ChatIndex.findOne({ tenantId, chatKey }).lean();
        if (!chat) return;

        // 🔒 Soft delete
        await ChatIndex.updateOne(
            { tenantId, chatKey },
            { $set: { isActive: false } }
        );

        await Message.updateMany(
            { tenantId, chatKey },
            { $set: { isActive: false } }
        );

        // 🔄 1) TÜM ADMINLER
        await emitActiveChats(tenantId);

        // 🔄 2) OWNER AGENT
        if (chat.ownerAgentId) {
            await emitActiveChats(tenantId, chat.ownerAgentId, chat.accountId);
        }

        // 🔄 3) ASSIGNED AGENT (aynı değilse)
        if (
            chat.assignedAgentId &&
            chat.assignedAgentId !== chat.ownerAgentId
        ) {
            await emitActiveChats(tenantId, chat.assignedAgentId, chat.accountId);
        }

        // (opsiyonel) UI için anlık event
        io.to(`admin:tenant:${tenantId}`).emit("chat-deleted");
    });

    socket.on("assign-chat", async (payload) => {
        const decrypted = decryptMessage(payload.data);
        const parsed = JSON.parse(decrypted);
        const { chatKey, agentId } = parsed
        console.log(parsed)
        if (!chatKey || !agentId) return;

        // 🔍 Chat'i bul
        const chat = await ChatIndex.findOne({ tenantId, chatKey }).lean();
        console.log(chat)
        if (!chat) return;

        const oldAgentId = chat.assignedAgentId || chat.ownerAgentId;

        // 🔍 Yeni agent bilgisi
        const agent = await TenantAgent.findOne({
            tenantId,
            agentId,
        }).lean();

        console.log(agent)

        if (!agent) {
            socket.emit("tg-error", "Agent bulunamadı");
            return;
        }

        // 🔄 ChatIndex update
        await ChatIndex.updateOne(
            { tenantId, chatKey },
            {
                $set: {
                    assignedAgentId: String(agentId),
                    assignedAgentExtension: agent.extension,
                    isActive: true,
                },
            }
        );

        // 🔄 ADMIN → herkes güncellensin
        await emitActiveChats(tenantId);

        // 🔄 ESKİ AGENT → sohbet düşsün
        if (oldAgentId && oldAgentId !== String(agentId)) {
            await emitActiveChats(tenantId, oldAgentId, chat.accountId);
        }

        // 🔄 YENİ AGENT → sohbet gelsin
        await emitActiveChats(tenantId, agentId, chat.accountId);

        const payload1 = {
            chatKey,
            agentId,
            extension: agent.extension
        }

        const json1 = JSON.stringify(payload1);
        const encrypted1 = encryptMessage(json1)

        // (opsiyonel) UI için bilgi
        io.to(`admin:tenant:${tenantId}`).emit("chat-assigned", {
            data: encrypted1
        });
    });

}

// ====================================================
// AGENT SOCKET EVENTLERİ
// ====================================================
async function setupAgentSocket(socket, tenantId, agentId, extension, token, userTitle, role) {

    // Bağlı agenta atanmış aktif Telegram hesaplarını gönder
    const agentSessions = await TelegramSession.find({ tenantId, assignedAgents: extension });
    // console.log(agentSessions)
    socket.emit("active-telegram-sessions", agentSessions);

    // Aktif sohbetler bağlantı anında gönderilmiyor, agent get-active-chats eventi ile isteyecek
    socket.on('get-active-chats', async (payload) => {
        const { accountId } = payload || {};
        console.log("debug -->", payload)

        if (!accountId) {
            socket.emit("tg-error", "accountId zorunludur");
            return;
        }
        const list = await buildAgentActiveChatsList(tenantId, agentId, accountId);
        const json = JSON.stringify(list);
        const encrypted = encryptMessage(json)
        socket.emit("active-chats", { data: encrypted });
    });

    console.log(`🟩 AGENT bağlandı → ${tenantId}:${agentId}`);

    socket.join(`agent:${tenantId}:${agentId}`);

    await TenantAgent.findOneAndUpdate(
        { tenantId, agentId },
        {
            tenantId,
            agentId,
            role,
            extension,
            userTitle,
            updatedAt: new Date(),
        },
        { upsert: true, new: true }
    );

    await emitTenantAgents(tenantId);

    // const status = await checkTelegramSessionStatus(tenantId, agentId);
    // socket.emit("tg-session-status", status);

    // Agent mesaj gönderebilir
    socket.on("send-message", (payload) =>
        handleSendMessage(socket, tenantId, agentId, payload, role = "agent", extension)
    );

    socket.on("get-chat", async (payload) => {
        const decrypted = decryptMessage(payload.data);
        const parsed = JSON.parse(decrypted);
        const { chatKey, count } = parsed
        try {
            // 1) Sohbet gerçekten bu agent'a atanmış mı?
            const chat = await ChatIndex.findOne({
                tenantId,
                chatKey,
                isActive: true,
                assignedAgentId: String(agentId),
            }).lean();
            if (!chat) {
                socket.emit("error", {
                    code: "CHAT_NOT_ASSIGNED",
                    message: "Bu sohbet size atanmadığı için geçmişi görüntüleyemezsiniz.",
                    chatKey,
                });
                return;
            }
            // 2) Agent, bu tenant için atanmış Telegram numarasından mı erişiyor?
            const session = await TelegramSession.findOne({ tenantId, assignedAgents: extension });
            if (!session) {
                socket.emit("error", {
                    code: "SESSION_NOT_ASSIGNED",
                    message: "Bu Telegram hesabı size atanmadığı için geçmişi görüntüleyemezsiniz.",
                    chatKey,
                });
                return;
            }
            // 📜 3) Mesaj geçmişi
            const total = await Message.countDocuments({
                tenantId,
                chatKey,
                isActive: true,
            });
            const skip = Math.max(total - count, 0);
            const msgs = await Message.find({
                tenantId,
                chatKey,
                isActive: true,
            })
                .sort({ timestamp: 1 })
                .skip(skip)
                .limit(count);
            const payload = {
                chatKey,
                messages: msgs
            }
            const json = JSON.stringify(payload);
            const encrypted = encryptMessage(json)
            socket.emit("chat-history", { data: encrypted });
        } catch (err) {
            console.error("get-chat error:", err);
            socket.emit("error", {
                code: "GET_CHAT_FAILED",
                message: "Sohbet geçmişi alınırken hata oluştu.",
            });
        }
    });


    socket.on("disconnect", async () => {
        const { tenantId, agentId } = socket.handshake.query;
        if (!tenantId || !agentId) return;

        await TenantAgent.deleteOne({ tenantId, agentId });

        await emitTenantAgents(tenantId);
    });
}

// ====================================================
// SESSION VARSA → DOĞRUDAN BAĞLAN
// ====================================================
async function connectWithSession(tenantId, accountId, sessionString, socket) {
    const key = buildKey(tenantId, accountId);

    console.log(`🔁 Session ile bağlanıyor → ${key}`);

    const client = new TelegramClient(new StringSession(sessionString), apiId, apiHash, {
        connectionRetries: 5,
    });

    tgClients.set(key, client);

    await client.connect();

    socket.emit("tg-login-success", { session: true });

    console.log(`✔ Telegram session ile bağlandı: ${key}`);

    startMessageListener(tenantId, accountId);
}

// ====================================================
// SESSION YOKSA → TELEFON / KOD AL
// ====================================================
async function connectWithoutSession(tenantId, agentId, socket, extension, phone) {
    const key = buildKey(tenantId, phone);

    console.log(`📱 İlk kez giriş yapılıyor → ${key}`);

    const client = new TelegramClient(new StringSession(""), apiId, apiHash, {
        connectionRetries: 5,
    });

    tgClients.set(key, client);

    await client.start({
        phoneNumber: async () => {
            if (phone) {
                return phone;
            }
            socket.emit("tg-need-phone");
            return await waitForEvent(socket, "tg-phone");
        },
        phoneCode: async () => {
            socket.emit("tg-need-code");
            return await waitForEvent(socket, "tg-code");
        },
        password: async () => {
            socket.emit("tg-need-password");
            return await waitForEvent(socket, "tg-password");
        },
        onError: (err) => console.error("Login Error:", err),
    });

    const sessionString = client.session.save();

    await TelegramSession.findOneAndUpdate(
        { tenantId, accountId: phone },
        { session: sessionString, agentExtension: extension },
        { upsert: true }
    );

    console.log(`💾 Telegram session MongoDB’ye kaydedildi → ${key}`);

    socket.emit("tg-login-success", { session: false });

    startMessageListener(tenantId, phone);
}

// ====================================================
// TELEGRAM MESAJ DİNLEME
// ====================================================
function startMessageListener(tenantId, accountId, agentEx) {
    const key = buildKey(tenantId, accountId);
    const client = tgClients.get(key);
    if (!client) return;

    client.addEventHandler(async (event) => {
        try {
            const message = event.message;
            if (!message || !event.isPrivate) return;

            console.log(message)

            const me = await client.getMe();


            const receiverPhone = me.phone || null;

            let body = message.text || "";
            let media = null;

            if (message.media) {
                const buffer = await client.downloadMedia(message.media);
                const base64 = buffer.toString("base64");

                // 📸 FOTOĞRAF
                if (message.media.photo) {
                    media = {
                        data: base64,
                        mimetype: "image/jpeg",   // Telegram foto default
                        fileName: null,
                        type: "image",
                    };
                }

                // 🎥 / 📄 DOCUMENT (video, pdf, dosya)
                else if (message.media.document) {
                    const doc = message.media.document;

                    const filenameAttr = doc.attributes?.find(
                        a => a.className === "DocumentAttributeFilename"
                    );

                    media = {
                        data: base64,
                        mimetype: doc.mimeType || "application/octet-stream",
                        fileName: filenameAttr?.fileName || null,
                        type:
                            doc.mimeType?.startsWith("video/")
                                ? "video"
                                : doc.mimeType === "application/pdf"
                                    ? "pdf"
                                    : "file",
                    };
                }
            }


            const sender = await message.getSender(); // ✅ DOĞRU YER
            const telegramUserId = sender.id?.value
                ? String(sender.id.value)
                : String(sender.id);

            const { telegramname, name, chatKey, clientPhone } =
                await getCustomerNameFromCacheOrPacket(
                    client,
                    tenantId,
                    telegramUserId,
                    sender
                );

            console.log("chatKey -->", chatKey)

            // 💾 DB
            const savedMessage = await saveMessageToDB({
                tenantId,
                accountId: clientPhone,
                chatKey,

                fromType: "customer",
                from: sender.username || telegramUserId,
                to: String(accountId),

                body,
                media,

                agentId: null,
                adminId: null,
                timestamp: Date.now(),
            });

            let chat = await ChatIndex.findOne({ tenantId, chatKey }).lean();

            let targetAgentId = null;

            if (!chat) {
                // 🆕 Yeni sohbet → kimseye atanma
                // await ensureChatIndex({
                //   tenantId,
                //   chatKey,
                //   telegramname,
                //   name,
                //   ownerAgentId: null,
                //   assignedAgentId: null,
                //   assignedAgentExtension: null,
                //   accountId: clientPhone,
                // });

                await ChatIndex.create({
                    tenantId,
                    chatKey,
                    telegramname,
                    name,
                    ownerAgentId: null,
                    assignedAgentId: null,
                    assignedAgentExtension: null,
                    accountId: clientPhone,
                    lastMessageAt: new Date(),
                    isActive: true,
                });

            } else {
                // ♻️ Var olan chat → SADECE zaman güncelle
                await ChatIndex.updateOne(
                    { tenantId, chatKey },
                    {
                        $set: {
                            lastMessageAt: new Date(),
                            isActive: true,
                        },
                    }
                );

                targetAgentId = chat.assignedAgentId || chat.ownerAgentId;
            }


            const payload = savedMessage.toObject();

            const encryptPayload = {
                chatKey,
                message: payload
            }

            const json = JSON.stringify(encryptPayload);
            const encrypted = encryptMessage(json)

            // 👤 SADECE atanmış agent varsa
            if (targetAgentId) {
                io.to(`agent:${tenantId}:${targetAgentId}`).emit("message", {
                    data: encrypted
                });

                await emitActiveChats(tenantId, targetAgentId, clientPhone);
            }

            // 👑 Adminler HER ZAMAN görür
            io.to(`admin:tenant:${tenantId}`).emit("new-message", {
                data: encrypted
            });

            await emitActiveChats(tenantId);

            // await emitActiveChats(tenantId, agentId, clientPhone);

        } catch (err) {
            console.error("TG message handler error:", err);
        }
    }, new NewMessage({}));
}

// ====================================================
// MESAJ GÖNDERME (Admin + Agent ortak)
// ====================================================
async function handleSendMessage(
    socket,
    tenantId,
    agentId, // UI'dan yazan kişi (admin / agent)
    payload,
    role,
    extension
) {
    const decrypted = decryptMessage(payload.data);
    const parsed = JSON.parse(decrypted);
    let { chatId, message, chatKey, name, accountId } = parsed;

    console.log(parsed)

    const key = buildKey(tenantId, accountId);
    const client = tgClients.get(key);
    const me = await client.getMe();


    // =====================================================
    // 1️⃣ ChatIndex bul
    // =====================================================
    let chat = await ChatIndex.findOne({ tenantId, chatKey }).lean();
    // Eğer agent ise ve chat varsa, accountId override: Sohbet hangi numaradan başlatılmışsa o numara üzerinden devam etsin
    if (chat && chat.accountId) {
        accountId = chat.accountId;
    }

    // =====================================================
    // 2️⃣ Agent yetki kontrolü (multi hesap için assignedAgents ve accountId)
    // =====================================================
    let session = null;
    if (role === "agent" && chat) {
        // accountId zorunlu
        if (!accountId) {
            socket.emit("tg-error", "accountId zorunludur");
            return;
        }
        // Sadece kendisine atanmış session üzerinden mesaj atabilir
        session = await TelegramSession.findOne({ tenantId, accountId, assignedAgents: extension });
        if (!session) {
            socket.emit(
                "tg-error",
                "Bu Telegram hesabı size atanmadığı için mesaj gönderemezsiniz."
            );
            return;
        }
    }

    // =====================================================
    // 3️⃣ Chat yoksa → ilk mesaj → owner = agent
    // =====================================================
    if (!chat) {
        const [, telegramname] = chatKey.split("-");

        await ensureChatIndex({
            tenantId,
            chatKey,
            telegramname,
            name,
            ownerAgentId: String(agentId),
            assignedAgentId: String(agentId),
            assignedAgentExtension: extension,
            accountId: `+${me.phone}`
        });

        chat = {
            chatKey,
            ownerAgentId: String(agentId),
            assignedAgentId: String(agentId),
        };
    }

    const ownerAgentId = String(chat.ownerAgentId);
    const assignedAgentId = String(chat.assignedAgentId);
    const assignedAgentExt = String(chat.assignedAgentExtension);

    // =====================================================
    // 4️⃣ Telegram client çöz (sadece accountId ile)
    // =====================================================
    if (!accountId) {
        socket.emit("tg-error", "accountId zorunludur");
        return;
    }

    if (!client) {
        socket.emit("tg-error", "Bu sohbete ait aktif bir Telegram oturumu bulunamadı.");
        return;
    }
    const usedAgentId = accountId;
    console.log(`📨 Telegram send via accountId ${usedAgentId}`);

    // =====================================================
    // 5️⃣ Telegram’a gönder
    // =====================================================
    try {
        if (typeof message === "string") {
            await client.sendMessage(chatId, { message });

        } else if (typeof message === "object" && message.data) {
            const approxSizeMB =
                (message.data.length * 3) / 4 / (1024 * 1024);

            if (approxSizeMB > 64) {
                socket.emit("tg-error", "Medya 64 MB’tan büyük olamaz");
                return;
            }

            if (message.mimetype?.startsWith("image/")) {
                await sendTelegramPhotoNative(client, chatId, message);
            } else {
                await sendTelegramDocumentNative(client, chatId, message);
            }

        } else {
            socket.emit("tg-error", "Geçersiz mesaj formatı");
            return;
        }

        // =====================================================
        // 6️⃣ DB’ye kaydet (GERÇEK Telegram hesabı ile)
        // =====================================================
        const isMedia = typeof message === "object";

        const savedMessage = await saveMessageToDB({
            tenantId,
            accountId: accountId,
            chatKey,

            fromType: role,
            from: String(agentId),
            to: String(chatId),

            body: isMedia ? "" : message,
            media: isMedia
                ? {
                    mimetype: message.mimetype,
                    data: message.data,
                    fileName: message.fileName || null,
                    type: message.type || "file",
                }
                : null,

            agentId: usedAgentId,          // 🔥 hangi TG hesabı kullandı
            adminId: role === "admin" ? String(agentId) : null,
            timestamp: Date.now(),
            agentExtension: extension,
        });

        // =====================================================
        // 7️⃣ ChatIndex güncelle (OWNER ASLA DEĞİŞMEZ)
        // =====================================================
        const [, telegramname] = chatKey.split("-");

        const nextAssignedAgentId =
            role === "admin" ? assignedAgentId : String(agentId);

        const nextAssignedAgentEx =
            role === "admin" ? assignedAgentExt : String(extension);

        await ensureChatIndex({
            tenantId,
            chatKey,
            telegramname,
            name,
            ownerAgentId,
            assignedAgentId: nextAssignedAgentId,
            assignedAgentExtension: nextAssignedAgentEx,
            accountId: `+${me.phone}`
        });

        // =====================================================
        // 8️⃣ FRONTEND EMIT
        // =====================================================
        const payload = savedMessage.toObject();

        const encryptPayload = {
            chatKey,
            message: payload
        }

        const json = JSON.stringify(encryptPayload);
        const encrypted = encryptMessage(json)

        // Owner
        io.to(`agent:${tenantId}:${ownerAgentId}`).emit("message", {
            data: encrypted
        });

        // Assigned (farklıysa)
        if (assignedAgentId && assignedAgentId !== ownerAgentId) {
            io.to(`agent:${tenantId}:${assignedAgentId}`).emit("message", {
                data: encrypted
            });
        }

        // Adminler
        io.to(`admin:tenant:${tenantId}`).emit("new-message", {
            data: encrypted
        });

        // Active chats
        await emitActiveChats(tenantId);
        await emitActiveChats(tenantId, ownerAgentId, accountId);

        if (assignedAgentId !== ownerAgentId) {
            await emitActiveChats(tenantId, assignedAgentId, accountId);
        }

    } catch (err) {
        console.error("Mesaj gönderim hatası:", err);
        socket.emit("tg-error", "Mesaj gönderilemedi");
    }
}



// ====================================================
// SUNUCU BAŞLANGICINDA TÜM SESSIONLARI OTOMATİK YÜKLE
// ====================================================
async function initializeAllTelegramSessions() {
    console.log("🔍 DB'deki Telegram sessionlar yükleniyor...");

    const sessions = await TelegramSession.find({});

    for (const s of sessions) {
        const key = `${s.tenantId}:${s.accountId}`;

        try {
            console.log(`♻ Session restore → ${key}`);

            const client = new TelegramClient(
                new StringSession(s.session),
                apiId,
                apiHash,
                { connectionRetries: 5 }
            );

            await client.connect();

            tgClients.set(key, client);

            // Telegram mesaj listener aç
            startMessageListener(s.tenantId, s.accountId, s.agentExtension);

            console.log(`✔ Başarıyla bağlandı → ${key}`);

        } catch (err) {
            console.log(`❌ Session yüklenemedi → ${key}`, err);
        }
    }

    console.log("✅ Tüm daha önce giriş yapılmış TG hesapları aktif!");
}

// ====================================================
// POST → TELEGRAM SESSION KAPAT
// ====================================================
app.post("/api/telegram/logout", async (req, res) => {
    const { tenantId, accountId } = req.body;

    if (!tenantId || !accountId) {
        return res.status(400).json({
            success: false,
            message: "tenantId ve agentId zorunludur",
        });
    }

    const key = buildKey(tenantId, accountId);

    try {
        // 1️⃣ Aktif Telegram client varsa kapat
        const client = tgClients.get(key);
        if (client) {
            try {
                await client.disconnect();
            } catch (e) {
                console.warn("Telegram client disconnect error:", e.message);
            }
            tgClients.delete(key);
        }

        // 2️⃣ DB'den session sil
        await TelegramSession.deleteOne({ tenantId, accountId });

        // 3️⃣ (Opsiyonel) Agent socketine bildir
        // io.to(`agent:${tenantId}:${agentId}`).emit("tg-logged-out", {
        //   tenantId,
        //   agentId,
        // });

        return res.json({
            success: true,
            message: "Telegram oturumu başarıyla kapatıldı",
        });

    } catch (err) {
        console.error("Telegram logout error:", err);
        return res.status(500).json({
            success: false,
            message: "Telegram oturumu kapatılamadı",
        });
    }
});

app.post("/api/tg/find-latest-chatkey", async (req, res) => {
    try {
        const { tenantId, telegramname } = req.body;

        if (!tenantId || !telegramname) {
            return res.status(400).json({
                success: false,
                error: "tenantId, telegramname ve name gereklidir.",
            });
        }

        // Aynı müşteri + aynı isim için en son aktif chat
        const chat = await ChatIndex.findOne({
            tenantId,
            telegramname: String(telegramname),
            isActive: true,
        })
            .sort({ lastMessageAt: -1 }) // en güncel sohbet
            .lean();

        if (!chat) {
            return res.json({
                success: false,
                error: "Bu müşteri için bir Telegram sohbeti bulunamadı",
            });
        }

        return res.json({
            success: true,
            chatKey: chat.chatKey,
            telegramname: chat.telegramname,
            accountId: chat.accountId, // hangi TG hattı
        });

    } catch (err) {
        console.error("❌ Telegram ChatKey arama hatası:", err);
        return res.status(500).json({
            success: false,
            error: err.message,
        });
    }
});

// ====================================================
server.listen(2056, async () => {
    console.log("🚀 Telegram Multi Server Başladı → 2056");
    await initializeAllTelegramSessions();
});
