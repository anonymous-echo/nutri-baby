import { VercelRequest, VercelResponse } from '@vercel/node';
import prisma from '../lib/prisma';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

// Helper to handle response
const sendResponse = (res: VercelResponse, status: number, data: any) => {
    return res.status(status).json(data);
};

// Safe BigInt serialization
const safeJSON = (data: any) => {
    return JSON.parse(JSON.stringify(data, (key, value) =>
        typeof value === 'bigint' ? value.toString() : (key === 'password' ? undefined : value)
    ));
};

export default async function handler(req: VercelRequest, res: VercelResponse) {
    const { url = '', method } = req;

    // Router logic based on URL suffix assuming rewrites preserve path or pass as query
    // Vercel rewrite: /api/auth/login -> dest: /api/auth => req.url might be /api/auth?code=... OR /api/auth/login 
    // Actually Vercel rewrites: destination file receives the request defined in source IF it's a file match.
    // If I rewrite /api/auth/(.*) -> /api/auth, the req.url seen by node is relative to the function? No, usually absolute.
    // We'll rely on string matching the end of the URL.

    if (method !== 'POST') {
        return sendResponse(res, 405, { message: 'Method Not Allowed' });
    }

    try {
        if (url.includes('/login/credential')) {
            return await handleCredentialLogin(req, res);
        } else if (url.includes('/register')) {
            return await handleRegister(req, res);
        } else if (url.includes('/login')) { // Default login
            return await handleCodeLogin(req, res);
        } else {
            return sendResponse(res, 404, { message: 'Auth endpoint not found', url });
        }
    } catch (error) {
        console.error('Auth Error:', error);
        return sendResponse(res, 500, { message: 'Internal Server Error' });
    }
}

async function handleCredentialLogin(req: VercelRequest, res: VercelResponse) {
    const { phone, password } = req.body;
    if (!phone || !password) return sendResponse(res, 400, { message: 'Phone/Pass required' });

    const user = await prisma.user.findUnique({ where: { phone } });
    if (!user || !user.password) return sendResponse(res, 401, { message: 'Invalid credentials' });

    const isValid = await bcrypt.compare(password, user.password);
    if (!isValid) return sendResponse(res, 401, { message: 'Invalid credentials' });

    await prisma.user.update({
        where: { id: user.id },
        data: { lastLoginTime: new Date() }
    });

    const token = jwt.sign({ userId: user.id.toString(), phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
    return sendResponse(res, 200, { token, userInfo: safeJSON(user) });
}

async function handleRegister(req: VercelRequest, res: VercelResponse) {
    const { phone, password, nickname } = req.body;
    if (!phone || !password) return sendResponse(res, 400, { message: 'Phone/Pass required' });

    const existing = await prisma.user.findUnique({ where: { phone } });
    if (existing) return sendResponse(res, 409, { message: 'User already exists' });

    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await prisma.user.create({
        data: {
            phone,
            password: hashedPassword,
            nickname: nickname || `User-${phone.slice(-4)}`,
            avatarUrl: 'https://cube.elemecdn.com/3/7c/3ea6beec64369c2642b92c6726f1epng.png',
            lastLoginTime: new Date()
        }
    });

    const token = jwt.sign({ userId: user.id.toString(), phone: user.phone }, JWT_SECRET, { expiresIn: '7d' });
    return sendResponse(res, 201, { token, userInfo: safeJSON(user) });
}

async function handleCodeLogin(req: VercelRequest, res: VercelResponse) {
    const { code } = req.body;
    if (!code) return sendResponse(res, 400, { message: 'Code required' });

    // Mock/Wechat Logic
    let openid = code.startsWith('mock-') ? code : 'wechat-openid-' + Math.random().toString(36).substring(7);

    let user = await prisma.user.findUnique({ where: { openid } });

    if (!user) {
        user = await prisma.user.create({
            data: {
                openid,
                nickname: 'New User',
                avatarUrl: 'https://cube.elemecdn.com/3/7c/3ea6beec64369c2642b92c6726f1epng.png',
                lastLoginTime: new Date(),
            },
        });
    } else {
        await prisma.user.update({ where: { id: user.id }, data: { lastLoginTime: new Date() } });
    }

    const token = jwt.sign({ userId: user.id.toString(), openid: user.openid }, JWT_SECRET, { expiresIn: '7d' });
    return sendResponse(res, 200, { token, userInfo: safeJSON(user) });
}
