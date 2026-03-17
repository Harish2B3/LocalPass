const db = require('../database');

/**
 * Logs a user action to the audit_logs table.
 * @param {Object} req - The Express request object (to extract user ID and IP).
 * @param {string} action - The action name (e.g., 'LOGIN', 'VIEW_PASSWORD').
 * @param {string} details - Additional details about the action.
 * @param {number} [overrideUserId] - Optional user ID if not available in req (e.g., during login before token).
 */
const logAction = (req, action, details, overrideUserId = null) => {
    // Try to get user ID from headers (populated by auth middleware) or explicit argument
    // Note: req.userId might be set by requireAuth middleware
    const userId = overrideUserId || req.userId || (req.headers && req.headers['x-user-id']);

    // If we don't have a user ID, we can't log it against a user (unless we allow null/system logs)
    if (!userId) {
        console.warn(`[Audit] Skipping log for '${action}' - No user ID found.`);
        return;
    }

    const ipAddress = req.ip || req.connection.remoteAddress || 'unknown';

    const sql = 'INSERT INTO audit_logs (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)';
    db.run(sql, [userId, action, details, ipAddress], (err) => {
        if (err) {
            console.error('[Audit] Failed to insert log:', err.message);
        } else {
            // console.log(`[Audit] Logged: ${action} by User ${userId}`);
        }
    });
};

module.exports = { logAction };
