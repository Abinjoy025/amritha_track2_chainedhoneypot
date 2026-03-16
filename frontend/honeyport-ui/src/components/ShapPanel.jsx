import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from 'recharts'
import { Brain } from 'lucide-react'

const PALETTE = [
  '#ef4444', '#f97316', '#eab308',
  '#22c55e', '#06b6d4', '#8b5cf6',
]

export default function ShapPanel({ event }) {
  if (!event || event.type !== 'session_complete') {
    return (
      <section className="bg-[#0d1529] rounded-xl border border-blue-900/30 p-4 flex flex-col gap-2">
        <div className="flex items-center gap-2 mb-1">
          <Brain className="w-4 h-4 text-purple-400" />
          <h2 className="font-semibold text-sm tracking-wide text-blue-200 uppercase">
            XAI — SHAP Explanation
          </h2>
        </div>
        <p className="text-xs text-gray-500">
          Click a completed session in the Live Feed to see why the model flagged it.
        </p>
      </section>
    )
  }

  const shap   = event.shap ?? {}
  const top    = shap.top_features ?? []
  const base   = shap.base_value   ?? 0

  // Build chart data
  const chartData = top.map(f => ({
    name:  f.name.replace(/^(Fwd |Bwd )/, '').substring(0, 22),
    value: f.shap_value,
    full:  f.name,
  }))

  const absMax = Math.max(...chartData.map(d => Math.abs(d.value)), 0.01)

  return (
    <section className="bg-[#0d1529] rounded-xl border border-blue-900/30 p-4 flex flex-col gap-3">

      {/* Header */}
      <div className="flex items-center gap-2">
        <Brain className="w-4 h-4 text-purple-400" />
        <h2 className="font-semibold text-sm tracking-wide text-blue-200 uppercase">
          XAI — SHAP Explanation
        </h2>
      </div>

      {/* Prediction summary */}
      <div className="rounded-lg bg-[#111d3a] px-3 py-2 flex items-center justify-between">
        <div>
          <div className="text-xs text-gray-400">Predicted Class</div>
          <div className="text-base font-bold text-orange-300">{event.attack_type}</div>
        </div>
        <div className="text-right">
          <div className="text-xs text-gray-400">Confidence</div>
          <div className="text-base font-bold text-emerald-400">
            {(event.confidence * 100).toFixed(1)} %
          </div>
        </div>
        <div className="text-right">
          <div className="text-xs text-gray-400">Base value</div>
          <div className="text-base font-bold text-blue-300">{base.toFixed(3)}</div>
        </div>
      </div>

      {/* SHAP bar chart */}
      {chartData.length > 0 ? (
        <>
          <p className="text-xs text-gray-500">
            Top 3 features driving the prediction (SHAP values)
          </p>
          <div className="h-36">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={chartData}
                layout="vertical"
                margin={{ top: 0, right: 8, left: 0, bottom: 0 }}
              >
                <XAxis
                  type="number"
                  domain={[-absMax, absMax]}
                  tick={{ fill: '#94a3b8', fontSize: 10 }}
                  tickFormatter={v => v.toFixed(2)}
                />
                <YAxis
                  type="category"
                  dataKey="name"
                  width={130}
                  tick={{ fill: '#cbd5e1', fontSize: 10 }}
                />
                <Tooltip
                  contentStyle={{ background: '#0d1529', border: '1px solid #1e3a5f', fontSize: 12 }}
                  formatter={(v, _, props) => [v.toFixed(4), props.payload.full]}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {chartData.map((d, i) => (
                    <Cell
                      key={i}
                      fill={d.value >= 0 ? '#ef4444' : '#22c55e'}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Legend */}
          <div className="flex gap-4 text-xs text-gray-400">
            <span><span className="inline-block w-3 h-3 rounded-sm bg-red-500 mr-1" />Increases attack probability</span>
            <span><span className="inline-block w-3 h-3 rounded-sm bg-green-500 mr-1" />Decreases attack probability</span>
          </div>
        </>
      ) : (
        <p className="text-xs text-gray-500">No SHAP data available for this event.</p>
      )}

      {/* IPFS CID */}
      {event.ipfs_cid && (
        <div className="rounded bg-gray-900/60 p-2 text-xs">
          <span className="text-gray-500">IPFS CID: </span>
          <a
            href={event.ipfs_url}
            target="_blank"
            rel="noreferrer"
            className="font-mono text-cyan-400 hover:underline break-all"
          >
            {event.ipfs_cid}
          </a>
        </div>
      )}
    </section>
  )
}
