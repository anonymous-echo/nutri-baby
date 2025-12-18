import { VercelRequest, VercelResponse } from '@vercel/node';
import prisma from '../lib/prisma';
import { getUserFromRequest } from '../lib/auth';
import jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';

const safeJSON = (data: any) => {
    return JSON.parse(JSON.stringify(data, (key, value) =>
        typeof value === 'bigint' ? value.toString() : value
    ));
};

export default async function handler(req: VercelRequest, res: VercelResponse) {
    const { url = '' } = req;

    // Auth Check
    const user = await getUserFromRequest(req);
    if (!user) return res.status(401).json({ message: 'Unauthorized' });

    try {
        // 1. Invite (POST)
        if (url.includes('/invite') && req.method === 'POST') {
            return await handleInvite(req, res, user);
        }

        // 2. Join (POST)
        if (url.includes('/join') && req.method === 'POST') {
            return await handleJoin(req, res, user);
        }

        // Helper to extract string ID
        const getId = (): string | null => {
            const urlMatch = url.match(/\/(\d+)$/);
            if (urlMatch) return urlMatch[1];
            if (req.query.id) return Array.isArray(req.query.id) ? req.query.id[0] : req.query.id;
            return null;
        };

        const id = getId();
        if (id) {
            if (req.method === 'PUT') return await handleUpdate(req, res, user, id);
            if (req.method === 'DELETE') return await handleDelete(req, res, user, id);
            if (req.method === 'GET') return await handleGetOne(req, res, user, id);
        }

        // 4. Collection operations (GET List, POST Create)
        if (req.method === 'GET') return await handleList(req, res, user);
        if (req.method === 'POST') return await handleCreate(req, res, user);

        return res.status(404).json({ message: 'Not Found' });

    } catch (error) {
        console.error('Baby API Error:', error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
}

async function handleList(req: any, res: any, user: any) {
    const babies = await prisma.baby.findMany({
        where: { userId: BigInt(user.userId) },
        orderBy: { createdAt: 'desc' }
    });
    return res.status(200).json(safeJSON(babies));
}

async function handleCreate(req: any, res: any, user: any) {
    const { name, nickname, gender, birthDate, avatarUrl } = req.body;
    if (!name || !gender || !birthDate) return res.status(400).json({ message: 'Missing fields' });

    const baby = await prisma.baby.create({
        data: { name, nickname, gender, birthDate, avatarUrl, userId: BigInt(user.userId) }
    });
    return res.status(201).json(safeJSON(baby));
}

async function handleGetOne(req: any, res: any, user: any, id: string) {
    const baby = await prisma.baby.findUnique({ where: { id: BigInt(id) } });
    if (!baby) return res.status(404).json({ message: 'Not Found' });
    return res.status(200).json(safeJSON(baby));
}

async function handleUpdate(req: any, res: any, user: any, id: string) {
    const { name, nickname, gender, birthDate, avatarUrl } = req.body;
    const updated = await prisma.baby.update({
        where: { id: BigInt(id) },
        data: { name, nickname, gender, birthDate, avatarUrl }
    });
    return res.status(200).json(safeJSON(updated));
}

async function handleDelete(req: any, res: any, user: any, id: string) {
    await prisma.baby.delete({ where: { id: BigInt(id) } });
    return res.status(200).json({ message: 'Deleted' });
}

async function handleInvite(req: any, res: any, user: any) {
    const { babyId, role = 'editor' } = req.body;
    if (!babyId) return res.status(400).json({ message: 'Baby ID required' });

    const token = jwt.sign({
        babyId, inviterId: user.userId, role, type: 'invite'
    }, JWT_SECRET, { expiresIn: '24h' });

    const url = `${process.env.VITE_APP_URL || 'http://localhost:3000'}/join?token=${token}`;
    return res.status(200).json({ token, url });
}

async function handleJoin(req: any, res: any, user: any) {
    const { token } = req.body;
    if (!token) return res.status(400).json({ message: 'Token required' });

    try {
        const decoded: any = jwt.verify(token, JWT_SECRET);
        if (decoded.type !== 'invite') throw new Error('Invalid token');

        const babyId = BigInt(decoded.babyId);
        const userId = BigInt(user.userId);

        const existing = await prisma.babyCollaborator.findUnique({
            where: { babyId_userId: { babyId, userId } }
        });

        if (!existing) {
            const owner = await prisma.baby.findFirst({ where: { id: babyId, userId } });
            if (!owner) {
                await prisma.babyCollaborator.create({
                    data: { babyId, userId, role: decoded.role, relationship: 'family', accessType: 'permanent' }
                });
            }
        }
        return res.status(200).json({ message: 'Joined', babyId: decoded.babyId });
    } catch (e) {
        return res.status(400).json({ message: 'Invalid or expired token' });
    }
}
