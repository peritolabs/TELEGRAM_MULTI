const mongoose = require("mongoose");

const ChatIndexSchema = new mongoose.Schema({
  tenantId: { type: String, required: true },
  chatKey: { type: String, required: true },
  accountId: { type: String, required: true },

  telegramname: { type: String, required: true },
  name: { type: String },

  ownerAgentId: { type: String },
  assignedAgentId: { type: String },
  assignedAgentExtension: { type: String },
  isActive: { type: Boolean, default: true, index: true },

  lastMessageAt: { type: Date },
}, { timestamps: true });

// 🔒 TEK DOĞRU UNIQUE INDEX
ChatIndexSchema.index(
  { tenantId: 1, chatKey: 1 },
  { unique: true }
);

module.exports = mongoose.model("ChatIndex", ChatIndexSchema);
