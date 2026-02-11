const mongoose = require("mongoose");

const TelegramSessionSchema = new mongoose.Schema({
  tenantId: { type: String, required: true },
  accountId: { type: String, required: true },
  agentExtension: { type: String }, // Artık zorunlu değil, backward compatibility için tutuldu

  ownerAdminId: { type: String }, // Hesabı bağlayan adminin id'si (isteğe bağlı)

  session: { type: String, required: true },
  phoneNumber: { type: String },
  extension: { type: String },
  assignedAgents: { type: [String] }, // Bu hesaba erişebilecek agentId listesi

  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },

});

TelegramSessionSchema.index({ tenantId: 1, accountId: 1 }, { unique: true });

module.exports = mongoose.model("TelegramSession", TelegramSessionSchema);
