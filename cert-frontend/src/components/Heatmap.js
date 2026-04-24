import React, { useState } from 'react';
import './Heatmap.css';

/**
 * Reusable heatmap component.
 * Props:
 *   title      — string
 *   x_labels   — string[]
 *   y_labels   — string[]
 *   values     — number[][] (rows = y_labels, cols = x_labels)
 */
export default function Heatmap({ title, x_labels = [], y_labels = [], values = [] }) {
  const [tooltip, setTooltip] = useState(null);

  if (!x_labels.length || !y_labels.length || !values.length) {
    return (
      <div className="heatmap-empty">
        <p>No data available for {title}</p>
      </div>
    );
  }

  const allVals = values.flat().filter(v => typeof v === 'number');
  const maxVal = Math.max(...allVals, 1);

  function intensity(val) {
    if (!val || val === 0) return 0;
    return val / maxVal;
  }

  function cellColor(val) {
    const t = intensity(val);
    if (t === 0) return 'rgba(15,23,42,0.6)';
    // Blue → Amber → Red gradient
    if (t < 0.33) {
      const a = t / 0.33;
      return `rgba(56,189,248,${0.15 + a * 0.45})`;
    }
    if (t < 0.66) {
      const a = (t - 0.33) / 0.33;
      return `rgba(245,158,11,${0.3 + a * 0.4})`;
    }
    const a = (t - 0.66) / 0.34;
    return `rgba(220,38,38,${0.5 + a * 0.5})`;
  }

  return (
    <div className="heatmap-wrap">
      <div className="heatmap-title">{title}</div>
      <div className="heatmap-scroll">
        <div
          className="heatmap-grid"
          style={{ gridTemplateColumns: `minmax(90px,auto) repeat(${x_labels.length}, minmax(28px,1fr))` }}
        >
          {/* Header row */}
          <div className="hm-cell hm-corner" />
          {x_labels.map((xl, xi) => (
            <div key={xi} className="hm-cell hm-header hm-x-label" title={xl}>
              {xl.length > 5 ? xl.slice(0, 4) + '…' : xl}
            </div>
          ))}

          {/* Data rows */}
          {y_labels.map((yl, yi) => (
            <React.Fragment key={yi}>
              <div className="hm-cell hm-y-label" title={yl}>
                {yl.length > 14 ? yl.slice(0, 13) + '…' : yl}
              </div>
              {x_labels.map((xl, xi) => {
                const val = (values[yi] || [])[xi] || 0;
                const bg = cellColor(val);
                return (
                  <div
                    key={xi}
                    className="hm-cell hm-data"
                    style={{ background: bg }}
                    onMouseEnter={(e) =>
                      setTooltip({ x: e.clientX, y: e.clientY, label: `${yl} / ${xl}: ${val}` })
                    }
                    onMouseLeave={() => setTooltip(null)}
                  >
                    {val > 0 ? val : ''}
                  </div>
                );
              })}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Legend */}
      <div className="hm-legend">
        <span className="hm-legend-item hm-low">Low</span>
        <div className="hm-legend-bar" />
        <span className="hm-legend-item hm-high">High</span>
      </div>

      {/* Tooltip */}
      {tooltip && (
        <div
          className="hm-tooltip"
          style={{ left: tooltip.x + 12, top: tooltip.y - 28, position: 'fixed' }}
        >
          {tooltip.label}
        </div>
      )}
    </div>
  );
}
