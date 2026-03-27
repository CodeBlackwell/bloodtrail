/**
 * BloodTrail Thermal Enhancement Layer
 * Overlays heat trails, chain gradients, quick-win flares on right panel only.
 */
const BloodTrailEnhance = (() => {
  let currentData = null;
  let activeChainId = null;

  const COLORS = {
    'white-hot': { thermal: '#ff6b2b', peak: '#fff4e0', cold: '#2266aa', quickWin: '#ffcc00' },
    'black-hot': { thermal: '#8b2500', peak: '#1a0800', cold: '#5588bb', quickWin: '#886600' },
  };

  function getPolarity() {
    return document.body.classList.contains('black-hot') ? 'black-hot' : 'white-hot';
  }

  function applyEnhancements(data) {
    currentData = data;
    const rightSvg = d3.select('#right-svg');

    rightSvg.select('defs').remove();
    const defs = rightSvg.insert('defs', ':first-child');
    _createHeatDefs(defs);

    if (window._btRightNodeGs) {
      window._btRightNodeGs.each(function(d) {
        const severity = _nodeSeverity(d, data);
        if (severity > 0) _addHeatTrails(d3.select(this), d, severity);
      });
    }

    if (data.chains && window._btRightEdges) {
      data.chains.forEach((chain, i) => _applyChainGlow(chain, i, defs));
    }

    if (data.quick_wins && window._btRightNodeGs) {
      _applyQuickWinFlares(data.quick_wins);
    }

    buildChainSidebar(data.chains || []);
  }

  function _createHeatDefs(defs) {
    const c = COLORS[getPolarity()];
    const grad = defs.append('linearGradient')
      .attr('id', 'heat-trail-grad')
      .attr('x1', 0).attr('y1', 0).attr('x2', 0).attr('y2', 1);
    grad.append('stop').attr('offset', '0%').attr('stop-color', c.thermal).attr('stop-opacity', 0.9);
    grad.append('stop').attr('offset', '60%').attr('stop-color', c.thermal).attr('stop-opacity', 0.4);
    grad.append('stop').attr('offset', '100%').attr('stop-color', c.thermal).attr('stop-opacity', 0);

    defs.append('filter').attr('id', 'heat-blur')
      .append('feGaussianBlur').attr('stdDeviation', 1.5);
  }

  function _nodeSeverity(node, data) {
    if (node.label === 'Domain' || node.props?.admincount) return 3;
    const isQuickWin = (data.quick_wins || []).some(q => q.node === node.id);
    if (isQuickWin) return 3;
    const inChain = (data.chains || []).some(ch =>
      ch.steps.some(s => s.from === node.id || s.to === node.id));
    if (inChain) return 2;
    const hasExploitableEdge = (data.edges || []).some(e =>
      (e.target_id === node.id) && e.edge !== 'MemberOf' && e.edge !== 'Contains');
    if (hasExploitableEdge) return 1;
    return 0;
  }

  function _getNodeRadius(g) {
    // Get bounding size from the path shape
    const shape = g.select('.node-shape').node();
    if (!shape) return 9;
    const bbox = shape.getBBox();
    return Math.max(bbox.width, bbox.height) / 2;
  }

  function _addHeatTrails(g, node, severity) {
    const count = Math.min(severity, 3);
    const baseLen = severity === 3 ? 42 : severity === 2 ? 28 : 16;
    const r = _getNodeRadius(g);

    for (let i = 0; i < count; i++) {
      const xOff = (i - (count - 1) / 2) * 4 + (Math.random() - 0.5) * 2;
      const len = baseLen + (Math.random() - 0.5) * 10;
      const cx1 = xOff + (Math.random() - 0.5) * 3;
      const cx2 = xOff + (Math.random() - 0.5) * 2;
      const sw = 2.5 - i * 0.5 + Math.random() * 0.5;

      g.append('path')
        .attr('class', `heat-trail trail-${i + 1}`)
        .attr('d', `M${xOff},${r} Q${cx1},${r + len * 0.4} ${xOff},${r + len * 0.7} Q${cx2},${r + len * 0.85} ${xOff},${r + len}`)
        .attr('fill', 'none')
        .attr('stroke', 'url(#heat-trail-grad)')
        .attr('stroke-width', sw)
        .attr('stroke-linecap', 'round')
        .attr('filter', 'url(#heat-blur)');

      if (i === 0) {
        g.append('circle')
          .attr('class', 'heat-point')
          .attr('cx', xOff).attr('cy', r + len + 3).attr('r', 2.5)
          .attr('fill', COLORS[getPolarity()].thermal)
          .attr('opacity', 0.5)
          .attr('filter', 'url(#heat-blur)');
      }
    }
  }

  function _applyChainGlow(chain, index, defs) {
    if (!chain.steps || !window._btRightEdges) return;
    const c = COLORS[getPolarity()];
    const gradId = `chain-grad-${index}`;

    const grad = defs.append('linearGradient').attr('id', gradId)
      .attr('x1', 0).attr('y1', 0).attr('x2', 1).attr('y2', 0);
    grad.append('stop').attr('offset', '0%').attr('stop-color', c.cold);
    grad.append('stop').attr('offset', '50%').attr('stop-color', c.thermal);
    grad.append('stop').attr('offset', '100%').attr('stop-color', c.peak);

    chain.steps.forEach(step => {
      if (!step.from || !step.to) return;
      window._btRightEdges
        .filter(d => d.source_id === step.from && d.target_id === step.to)
        .attr('class', 'edge-path edge-chain')
        .attr('stroke', `url(#${gradId})`)
        .attr('data-chain', chain.id)
        .style('stroke-dasharray', '4 16');
    });
  }

  function _applyQuickWinFlares(quickWins) {
    if (!window._btRightNodeGs) return;
    const qwNodes = new Set(quickWins.map(q => q.node));
    const c = COLORS[getPolarity()];

    window._btRightNodeGs.each(function(d) {
      if (!qwNodes.has(d.id)) return;
      const g = d3.select(this);
      const r = _getNodeRadius(g);
      const qw = quickWins.find(q => q.node === d.id);

      g.append('circle')
        .attr('class', 'qw-ring')
        .attr('r', r + 5)
        .attr('fill', 'none')
        .attr('stroke', c.quickWin)
        .attr('stroke-width', 1)
        .attr('stroke-dasharray', '3 3')
        .attr('opacity', 0.6)
        .style('animation', 'quick-win-flare 2s ease-in-out infinite');

      g.append('text')
        .attr('class', 'qw-label')
        .attr('dy', -(r + 10))
        .attr('text-anchor', 'middle')
        .attr('fill', c.quickWin)
        .attr('font-size', '0.45rem')
        .attr('font-family', 'JetBrains Mono, monospace')
        .attr('font-weight', 600)
        .text(qw?.type?.replace(/_/g, ' ').toUpperCase().slice(0, 22) || '');
    });
  }

  function buildChainSidebar(chains) {
    const sidebar = document.getElementById('chain-sidebar');
    if (!chains.length) { sidebar.innerHTML = ''; return; }

    sidebar.innerHTML = `<div class="sidebar-header">Attack Chains (${chains.length})</div>` +
      chains.map(ch => `
        <div class="chain-item" data-chain="${ch.id}">
          <span class="chain-name">${ch.name}</span>
          <span class="severity-badge severity-${ch.severity}">${ch.severity}</span>
        </div>
      `).join('');

    sidebar.querySelectorAll('.chain-item').forEach(el => {
      el.addEventListener('click', () => highlightChain(el.dataset.chain));
    });
  }

  function highlightChain(chainId) {
    if (!currentData) return;
    const isToggle = activeChainId === chainId;
    activeChainId = isToggle ? null : chainId;

    document.querySelectorAll('.chain-item').forEach(el => {
      el.classList.toggle('active', el.dataset.chain === activeChainId);
    });

    if (isToggle || !activeChainId) {
      if (window._btRightEdges) window._btRightEdges.style('opacity', null);
      if (window._btRightNodeGs) window._btRightNodeGs.style('opacity', null);
      return;
    }

    const chain = currentData.chains.find(c => c.id === chainId);
    if (!chain) return;

    const chainNodes = new Set();
    chain.steps.forEach(s => { if (s.from) chainNodes.add(s.from); if (s.to) chainNodes.add(s.to); });

    if (window._btRightEdges) {
      window._btRightEdges.style('opacity', d => {
        return (chainNodes.has(d.source_id) && chainNodes.has(d.target_id)) ? 0.9 : 0.05;
      });
    }
    if (window._btRightNodeGs) {
      window._btRightNodeGs.style('opacity', d => chainNodes.has(d.id) ? 1 : 0.1);
    }
  }

  function markAsPwned(nodeId) {
    if (!window._btEdges || !window._btRightNodeGs) return;
    const exploitableTypes = new Set([
      'AdminTo', 'CanRDP', 'CanPSRemote', 'GenericAll', 'GenericWrite',
      'WriteDacl', 'ForceChangePassword', 'AddKeyCredentialLink',
      'WriteAccountRestrictions', 'AllowedToDelegate', 'CoerceToTGT', 'ExecuteDCOM',
    ]);

    const adj = {};
    window._btEdges.forEach(e => {
      if (exploitableTypes.has(e.edge)) {
        adj[e.source_id] = adj[e.source_id] || [];
        adj[e.source_id].push(e.target_id);
      }
    });

    const visited = new Set([nodeId]);
    let frontier = [nodeId];
    const c = COLORS[getPolarity()];

    const wave = () => {
      if (!frontier.length) return;
      const next = [];
      frontier.forEach(nid => {
        window._btRightNodeGs.filter(d => d.id === nid).each(function() {
          const g = d3.select(this);
          g.select('.node-shape')
            .transition().duration(400)
            .attr('fill', c.peak)
            .attr('stroke', c.thermal)
            .attr('stroke-width', 2.5);
          g.append('circle')
            .attr('r', 0).attr('fill', 'none')
            .attr('stroke', c.thermal).attr('stroke-width', 2).attr('opacity', 0.8)
            .transition().duration(600)
            .attr('r', 40).attr('opacity', 0)
            .remove();
        });
        (adj[nid] || []).forEach(t => {
          if (!visited.has(t)) { visited.add(t); next.push(t); }
        });
      });
      frontier = next;
      if (next.length) setTimeout(wave, 200);
    };
    wave();
  }

  window.addEventListener('dblclick', (e) => {
    const group = e.target.closest('.node-group');
    if (group && group.closest('#right-panel')) {
      const nodeId = group.dataset.id;
      if (nodeId) markAsPwned(nodeId);
    }
  });

  function updateHeatTrailColors(polarity) {
    const c = COLORS[polarity];
    const rightSvg = d3.select('#right-svg');

    rightSvg.selectAll('#heat-trail-grad stop').attr('stop-color', c.thermal);
    rightSvg.selectAll('.heat-point').attr('fill', c.thermal);
    rightSvg.selectAll('.qw-ring').attr('stroke', c.quickWin);
    rightSvg.selectAll('.qw-label').attr('fill', c.quickWin);

    rightSvg.selectAll('[id^="chain-grad-"]').each(function() {
      const stops = d3.select(this).selectAll('stop');
      stops.filter((d, i) => i === 0).attr('stop-color', c.cold);
      stops.filter((d, i) => i === 1).attr('stop-color', c.thermal);
      stops.filter((d, i) => i === 2).attr('stop-color', c.peak);
    });
  }

  return { applyEnhancements, updateHeatTrailColors, highlightChain, markAsPwned };
})();
