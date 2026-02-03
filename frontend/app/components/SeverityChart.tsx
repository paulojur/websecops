'use client';

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const data = [
    { name: 'Critical', value: 400, color: '#ff0055' },
    { name: 'High', value: 300, color: '#ffb700' },
    { name: 'Medium', value: 300, color: '#00bcd4' },
    { name: 'Low', value: 200, color: '#00ff9d' },
];

export default function SeverityChart({ stats }: { stats: any }) {
    // In a real app we would use actual stats, but we might not have breakdown yet.
    // Let's try to infer if stats has it, or use mock for visual demo as user requested "visual rs"

    // Using mock data for the visual "wow" factor if stats are empty
    const chartData = stats.total_tracked > 0 ? [
        { name: 'Critical', value: stats.critical_count, color: '#ef4444' }, // red-500
        { name: 'High', value: stats.high_count, color: '#f97316' }, // orange-500
        { name: 'Other', value: stats.total_tracked - (stats.critical_count + stats.high_count), color: '#3b82f6' } // blue-500
    ] : data;

    return (
        <div className="h-48 w-full">
            <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                    <Pie
                        data={chartData}
                        cx="50%"
                        cy="50%"
                        innerRadius={40}
                        outerRadius={70}
                        paddingAngle={5}
                        dataKey="value"
                        stroke="none"
                    >
                        {chartData.map((entry, index) => (
                            <Cell key={`cell-${index}`} fill={entry.color} />
                        ))}
                    </Pie>
                    <Tooltip
                        contentStyle={{ backgroundColor: '#141419', borderColor: '#333', color: '#fff' }}
                        itemStyle={{ color: '#fff' }}
                    />
                </PieChart>
            </ResponsiveContainer>
        </div>
    );
}
