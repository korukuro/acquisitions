import aj from "../config/arcjet.js";
import { slidingWindow } from "@arcjet/node";
import logger from '#config/logger.js';

const securityMiddleware = async (req, res, next) => {
    try {
        const role = req.user?.role || 'guest';

        let limit;
        let message;

        switch (role) {
            case 'admin':
                limit = 20;
                message = 'Admin request limit exceeded';
                break;

            case 'user':
                limit = 10;
                message = 'User request limit exceeded';
                break;

            default:
                limit = 5;
                message = 'Guest request limit exceeded';
        }

        const client = aj.withRule(
            slidingWindow({
                mode: 'LIVE',
                interval: '1m',
                max: limit,
                name: `${role}-rate-limit`
            })
        );

        const decision = await client.protect(req);

        if (decision.isDenied() && decision.reason.isBot()) {
            logger.warn('Bot request blocked', {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                path: req.path
            });

            return res.status(403).json({
                error: 'Forbidden',
                message: 'Bot traffic is not allowed'
            });
        }

        if (decision.isDenied() && decision.reason.isShield()) {
            logger.warn('Shield request blocked', {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                path: req.path,
                method: req.method
            });

            return res.status(403).json({
                error: 'Forbidden',
                message: 'Shield protection triggered'
            });
        }

        if (decision.isDenied() && decision.reason.isRateLimit()) {
            logger.warn('Rate limit request blocked', {
                ip: req.ip,
                userAgent: req.get('User-Agent'),
                path: req.path
            });

            return res.status(429).json({
                error: 'Too Many Requests',
                message
            });
        }

        next();
    } catch (error) {
        logger.error('Security middleware error', error);

        return res.status(500).json({
            error: 'Internal server error',
            message: 'Something went wrong with security middleware'
        });
    }
};

export default securityMiddleware;