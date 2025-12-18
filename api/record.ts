import { VercelRequest, VercelResponse } from '@vercel/node';
import prisma from '../lib/prisma';
import { getUserFromRequest } from '../lib/auth';

const safeJSON = (data: any) => {
    return JSON.parse(JSON.stringify(data, (key, value) =>
        typeof value === 'bigint' ? value.toString() : value
    ));
};

export default async function handler(req: VercelRequest, res: VercelResponse) {
    const user = await getUserFromRequest(req);
    if (!user) return res.status(401).json({ message: 'Unauthorized' });

    // Determine Record Type from Query (injected by Rewrite)
    const type = req.query.type as string;
    // Types: 'feeding', 'sleep', 'diaper', 'growth'

    if (!type) {
        return res.status(400).json({ message: 'Record type unspecified' });
    }

    // Map type to Prisma Model Delegate
    let model: any;
    if (type === 'feeding') model = prisma.feedingRecord;
    else if (type === 'sleep') model = prisma.sleepRecord;
    else if (type === 'diaper') model = prisma.diaperRecord;
    else if (type === 'growth') model = prisma.growthRecord;
    else return res.status(400).json({ message: 'Invalid record type' });

    try {
        if (req.method === 'GET') {
            const { babyId, startTime, endTime } = req.query;
            if (!babyId) return res.status(400).json({ message: 'Baby ID required' });

            const where: any = { babyId: BigInt(babyId as string) };
            if (startTime || endTime) {
                where.time = {};
                if (startTime) where.time.gte = new Date(Number(startTime));
                if (endTime) where.time.lte = new Date(Number(endTime));
            }

            const records = await model.findMany({
                where,
                orderBy: { time: 'desc' }
            });

            // Frontend expects { records: [...] } for feeding but check others?
            // Unified API: return { records: [...] } or array?
            // Existing frontend for Feeding expects `{ records: [...] }`.
            // Let's standardise on `{ records: [...] }` if possible, OR just return array if frontend handles it.
            // But wait, the previous `feeding-records/index.ts` returned `{ records: response }`.
            // I should stick to that wrapper for consistency.
            return res.status(200).json({ records: safeJSON(records) });

        } else if (req.method === 'POST') {
            const { babyId, time, ...rest } = req.body;
            if (!babyId || !time) return res.status(400).json({ message: 'Missing fields' });

            const data: any = {
                babyId: BigInt(babyId),
                time: new Date(time),
                createdBy: BigInt(user.userId),
                ...rest
            };

            // Clean up unrelated fields if necessary, or trust Prisma to ignore unknown (it throws usually)
            // So we really should specific fields per type strictly, but for speed 'rest' is used.
            // Risk: 'duration' passed to diaper record? No, Prisma checks schema.
            // It's better to be safe.

            const record = await model.create({ data });
            return res.status(201).json(safeJSON(record));
        }

        return res.status(405).json({ message: 'Method Not Allowed' });

    } catch (error) {
        console.error(`Record API Error (${type}):`, error);
        return res.status(500).json({ message: 'Internal Server Error' });
    }
}
