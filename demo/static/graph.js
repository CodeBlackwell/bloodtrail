/**
 * BloodTrail D3 Force-Directed Graph Renderer
 * One simulation, two SVG panels, synced zoom.
 * Directed edges with arrows, shaped nodes, hierarchical y-force.
 */
const BloodTrailGraph = (() => {
  let simulation = null;
  let leftG, rightG, leftSvg, rightSvg;
  let graphData = null;
  let currentLayout = 'htree';
  let currentFilter = 'attacks';
  let layoutW = 0, layoutH = 0;

  // Node shapes: Domain=hexagon, Computer=rect, Group=diamond, User=circle
  const SHAPES = {
    Domain:   d3.symbol().type(d3.symbolStar).size(350),
    Computer: d3.symbol().type(d3.symbolSquare).size(200),
    Group:    d3.symbol().type(d3.symbolDiamond).size(220),
    User:     d3.symbol().type(d3.symbolCircle).size(200),
  };

  const NODE_COLORS = {
    Domain: 'var(--node-da)', User: 'var(--node-user)',
    Computer: 'var(--node-computer)', Group: 'var(--node-group)',
  };

  // Edge categories for color coding
  const EDGE_CATS = {
    access:   new Set(['AdminTo','CanRDP','CanPSRemote','ExecuteDCOM','HasSession']),
    acl:      new Set(['GenericAll','GenericWrite','WriteDacl','WriteOwner','ForceChangePassword','AddMember','Owns','AddSelf','WriteSPN','AllExtendedRights']),
    cred:     new Set(['AddKeyCredentialLink','ReadLAPSPassword','ReadGMSAPassword','SyncLAPSPassword']),
    deleg:    new Set(['AllowedToDelegate','AllowedToAct','WriteAccountRestrictions','AddAllowedToAct']),
    dcsync:   new Set(['GetChanges','GetChangesAll']),
    coerce:   new Set(['CoerceToTGT']),
    trust:    new Set(['TrustedBy']),
    member:   new Set(['MemberOf','Contains']),
  };

  function edgeCategory(type) {
    for (const [cat, set] of Object.entries(EDGE_CATS)) {
      if (set.has(type)) return cat;
    }
    return 'other';
  }

  // Hierarchical y-position targets
  function yTarget(node, h) {
    const band = { Domain: 0.12, Group: 0.38, Computer: 0.62, User: 0.78 };
    return (band[node.label] || 0.5) * h;
  }

  function nodeSize(node, enhanced) {
    if (!enhanced) {
      if (node.label === 'Domain') return 180;
      return 100;
    }
    if (node.label === 'Domain') return 250;
    if (node.props?.admincount) return 160;
    if (node.props?.unconstraineddelegation || node.props?.is_dc) return 150;
    return 110;
  }

  function shortName(name) {
    return name.split('@')[0].split('.')[0];
  }

  function initGraph(data) {
    graphData = data;
    d3.select('#left-svg').selectAll('*').remove();
    d3.select('#right-svg').selectAll('*').remove();
    if (simulation) simulation.stop();

    leftSvg = d3.select('#left-svg');
    rightSvg = d3.select('#right-svg');
    const rect = document.getElementById('left-panel').getBoundingClientRect();
    const w = rect.width, h = rect.height;

    const nodes = data.nodes.map(n => ({ ...n }));
    const nodeById = Object.fromEntries(nodes.map(n => [n.id, n]));
    const edges = data.edges
      .filter(e => nodeById[e.source_id] && nodeById[e.target_id])
      .map(e => ({ ...e, source: nodeById[e.source_id], target: nodeById[e.target_id] }));

    leftG = leftSvg.append('g');
    rightG = rightSvg.append('g');

    // Arrow markers for both panels
    _addMarkers(leftSvg, 'left');
    _addMarkers(rightSvg, 'right');

    // Edges as curved paths with arrows
    const leftEdgeGs = leftG.selectAll('.edge-group').data(edges).enter().append('g').attr('class', 'edge-group');
    const leftPaths = leftEdgeGs.append('path').attr('class', d => `edge-path edge-cat-${edgeCategory(d.edge)}`)
      .attr('marker-end', d => EDGE_CATS.member.has(d.edge) ? '' : 'url(#arrow-left)');
    const leftEdgeLabels = leftEdgeGs.append('text').attr('class', 'edge-label')
      .text(d => d.edge);

    const rightEdgeGs = rightG.selectAll('.edge-group').data(edges).enter().append('g').attr('class', 'edge-group');
    const rightPaths = rightEdgeGs.append('path')
      .attr('class', d => {
        const cat = edgeCategory(d.edge);
        const base = `edge-path edge-cat-${cat}`;
        if (cat !== 'member' && cat !== 'other') return `${base} edge-exploitable`;
        return base;
      })
      .attr('data-edge', d => d.edge)
      .attr('data-source', d => d.source_id)
      .attr('data-target', d => d.target_id)
      .attr('marker-end', d => EDGE_CATS.member.has(d.edge) ? '' : 'url(#arrow-right)');
    const rightEdgeLabels = rightEdgeGs.append('text').attr('class', 'edge-label edge-label-enhanced')
      .text(d => d.edge);

    // Node groups
    const makeNodes = (g, enhanced) => {
      const gs = g.selectAll('.node-group').data(nodes).enter().append('g')
        .attr('class', d => `node-group node-type-${d.label.toLowerCase()}`)
        .attr('data-id', d => d.id)
        .attr('data-label', d => d.label)
        .call(d3.drag()
          .on('start', (e, d) => { if (!e.active) simulation.alphaTarget(0.3).restart(); d.fx = d.x; d.fy = d.y; })
          .on('drag', (e, d) => { d.fx = e.x; d.fy = e.y; })
          .on('end', (e, d) => { if (!e.active) simulation.alphaTarget(0); d.fx = null; d.fy = null; })
        );
      // Shaped node
      gs.append('path')
        .attr('class', 'node-shape')
        .attr('d', d => {
          const gen = SHAPES[d.label] || SHAPES.User;
          return gen.size(nodeSize(d, enhanced))();
        })
        .attr('fill', d => NODE_COLORS[d.label] || 'var(--node-safe)');

      // Label — always visible
      gs.append('text')
        .attr('class', enhanced ? 'node-label visible' : 'node-label visible')
        .attr('dy', d => {
          const s = Math.sqrt(nodeSize(d, enhanced)) / 2;
          return -(s + 4);
        })
        .attr('text-anchor', 'middle')
        .text(d => shortName(d.name));

      return gs;
    };

    const leftNodeGs = makeNodes(leftG, false);
    const rightNodeGs = makeNodes(rightG, true);

    // Right panel: thermal stroke + glow
    rightNodeGs.select('.node-shape')
      .attr('stroke', d => d.label === 'Domain' ? 'var(--white-hot)' : 'var(--thermal)')
      .attr('stroke-width', 1.5)
      .style('filter', d => nodeSize(d, true) > 300 ? 'drop-shadow(0 0 6px var(--thermal-33))' : 'none');

    // Store refs
    window._btRightNodeGs = rightNodeGs;
    window._btRightEdges = rightPaths;
    window._btLeftEdges = leftPaths;
    window._btNodes = nodes;
    window._btEdges = edges;

    // Click
    leftNodeGs.on('click', (e, d) => selectNode(d.id));
    rightNodeGs.on('click', (e, d) => selectNode(d.id));

    layoutW = w;
    layoutH = h;

    // Simulation — forces configured by layout mode
    simulation = d3.forceSimulation(nodes)
      .force('link', d3.forceLink(edges).id(d => d.id))
      .force('collide', d3.forceCollide(16));

    _applyLayout(currentLayout);

    simulation.on('tick', () => {
        // Curved edges
        const curvePath = (d) => {
          const dx = d.target.x - d.source.x;
          const dy = d.target.y - d.source.y;
          const dr = Math.sqrt(dx * dx + dy * dy) * 1.5;
          return `M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`;
        };
        leftPaths.attr('d', curvePath);
        rightPaths.attr('d', curvePath);
        // Edge labels at midpoint
        const labelPos = (d) => {
          const mx = (d.source.x + d.target.x) / 2;
          const my = (d.source.y + d.target.y) / 2;
          // offset perpendicular to the arc
          const dx = d.target.x - d.source.x;
          const dy = d.target.y - d.source.y;
          const len = Math.sqrt(dx*dx + dy*dy) || 1;
          const off = 8;
          return { x: mx - (dy/len)*off, y: my + (dx/len)*off };
        };
        leftEdgeLabels.attr('x', d => labelPos(d).x).attr('y', d => labelPos(d).y);
        rightEdgeLabels.attr('x', d => labelPos(d).x).attr('y', d => labelPos(d).y);
        leftNodeGs.attr('transform', d => `translate(${d.x},${d.y})`);
        rightNodeGs.attr('transform', d => `translate(${d.x},${d.y})`);
      });

    setupZoomSync(leftSvg, rightSvg, leftG, rightG);

    // Apply edge filter after render (default: attacks only)
    requestAnimationFrame(() => _applyEdgeFilter(currentFilter));
  }

  // Build a d3.hierarchy from flat graph data via BFS from Domain root
  function _buildHierarchy(nodes, edges) {
    const root = nodes.find(n => n.label === 'Domain') || nodes[0];
    const adj = {};
    edges.forEach(e => {
      const sid = typeof e.source === 'object' ? e.source.id : e.source;
      const tid = typeof e.target === 'object' ? e.target.id : e.target;
      (adj[sid] = adj[sid] || []).push(tid);
      (adj[tid] = adj[tid] || []).push(sid);
    });

    // BFS from root, each node visited once
    const visited = new Set([root.id]);
    const tree = { id: root.id, children: [] };
    const queue = [tree];
    const treeNodeById = { [root.id]: tree };

    while (queue.length) {
      const parent = queue.shift();
      for (const nid of (adj[parent.id] || [])) {
        if (visited.has(nid)) continue;
        visited.add(nid);
        const child = { id: nid, children: [] };
        parent.children.push(child);
        treeNodeById[nid] = child;
        queue.push(child);
      }
    }

    // Attach orphans (nodes with no edges to the main tree)
    nodes.forEach(n => {
      if (!visited.has(n.id)) {
        const child = { id: n.id, children: [] };
        tree.children.push(child);
        treeNodeById[n.id] = child;
      }
    });

    return d3.hierarchy(tree);
  }

  function _applyLayout(mode) {
    if (!simulation) return;
    const w = layoutW, h = layoutH;

    // Clear forces
    simulation.force('center', null);
    simulation.force('charge', null);
    simulation.force('x', null);
    simulation.force('y', null);

    const link = simulation.force('link');
    const nodes = simulation.nodes();

    if (mode === 'force') {
      // Unpin all nodes, let forces drive
      nodes.forEach(n => { n.fx = null; n.fy = null; });
      simulation.force('charge', d3.forceManyBody().strength(-350));
      simulation.force('center', d3.forceCenter(w / 2, h / 2));
      simulation.force('y', d3.forceY(d => yTarget(d, h)).strength(0.12));
      link.distance(90).strength(0.7);
    }

    else if (mode === 'vtree' || mode === 'htree') {
      const hier = _buildHierarchy(nodes, window._btEdges || []);
      const pad = 40;
      const isV = mode === 'vtree';

      const treeLayout = d3.tree().size(
        isV ? [w - pad * 2, h - pad * 2] : [h - pad * 2, w - pad * 2]
      );
      treeLayout(hier);

      // Map tree positions back to simulation nodes
      const posById = {};
      hier.each(d => {
        posById[d.data.id] = isV
          ? { x: d.x + pad, y: d.y + pad }
          : { x: d.y + pad, y: d.x + pad };
      });

      nodes.forEach(n => {
        const pos = posById[n.id];
        if (pos) { n.fx = pos.x; n.fy = pos.y; }
      });

      // Minimal forces — just keep things tidy
      simulation.force('charge', null);
      link.distance(50).strength(0);
    }

    simulation.alpha(1).restart();
  }

  function setLayout(mode) {
    currentLayout = mode;
    simulation.nodes().forEach(n => { n.fx = null; n.fy = null; });
    _applyLayout(mode);
  }

  // Edge filter: 'attacks' hides MemberOf/Contains, dims unconnected nodes
  function _applyEdgeFilter(mode) {
    const STRUCTURAL = EDGE_CATS.member;
    const hideStructural = mode === 'attacks';

    // Build set of nodes that have at least one visible attack edge
    const attackConnected = new Set();
    if (hideStructural && window._btEdges) {
      window._btEdges.forEach(e => {
        if (!STRUCTURAL.has(e.edge)) {
          attackConnected.add(typeof e.source === 'object' ? e.source.id : e.source);
          attackConnected.add(typeof e.target === 'object' ? e.target.id : e.target);
        }
      });
    }

    // Toggle edge visibility on both panels
    d3.selectAll('.edge-group').each(function(d) {
      const isMember = STRUCTURAL.has(d.edge);
      d3.select(this).classed('edge-hidden', hideStructural && isMember);
    });

    // Dim nodes with no attack edges (right panel only for enhanced view)
    if (window._btRightNodeGs) {
      window._btRightNodeGs.classed('node-dimmed', d => {
        return hideStructural && !attackConnected.has(d.id);
      });
    }
  }

  function setEdgeFilter(mode) {
    currentFilter = mode;
    _applyEdgeFilter(mode);
  }

  function _addMarkers(svg, prefix) {
    const defs = svg.select('defs').size() ? svg.select('defs') : svg.append('defs');

    // Standard arrow
    defs.append('marker').attr('id', `arrow-${prefix}`)
      .attr('viewBox', '0 0 10 6').attr('refX', 14).attr('refY', 3)
      .attr('markerWidth', 7).attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path').attr('d', 'M0,0 L10,3 L0,6 Z')
      .attr('class', 'arrow-head');

    // Thermal arrow (right panel exploitable edges)
    defs.append('marker').attr('id', `arrow-hot-${prefix}`)
      .attr('viewBox', '0 0 10 6').attr('refX', 14).attr('refY', 3)
      .attr('markerWidth', 7).attr('markerHeight', 5)
      .attr('orient', 'auto')
      .append('path').attr('d', 'M0,0 L10,3 L0,6 Z')
      .attr('class', 'arrow-head-hot');
  }

  function setupZoomSync(svg1, svg2, g1, g2) {
    let syncing = false;
    const zoom = d3.zoom().scaleExtent([0.2, 5]).on('zoom', (e) => {
      if (syncing) return;
      syncing = true;
      g1.attr('transform', e.transform);
      g2.attr('transform', e.transform);
      svg1.call(zoom.transform, e.transform);
      svg2.call(zoom.transform, e.transform);
      syncing = false;
    });
    svg1.call(zoom);
    svg2.call(zoom);
  }

  function selectNode(nodeId) {
    d3.selectAll('.node-group').classed('selected', d => d.id === nodeId);
    const tooltip = document.getElementById('tooltip');
    const node = graphData.nodes.find(n => n.id === nodeId);
    if (!node) return;

    const related = graphData.edges.filter(e => e.source_id === nodeId || e.target_id === nodeId);
    const cmds = related
      .filter(e => e.edge !== 'MemberOf' && e.edge !== 'Contains')
      .map(e => {
        const tools = getEdgeCommands(e.edge);
        if (!tools.length) return '';
        const dir = e.source_id === nodeId ? `→ ${shortName(e.target_name)}` : `← ${shortName(e.source_name)}`;
        return `<div class="tool-name">${e.edge} ${dir}</div><div class="cmd-text">${tools.join(', ')}</div>`;
      }).filter(Boolean).slice(0, 5);

    if (cmds.length) {
      tooltip.innerHTML = `<div class="tool-name" style="font-size:0.8rem;margin-bottom:0.4rem">${node.name}</div>
        <div style="color:var(--text-faint);font-size:0.6rem;margin-bottom:0.3rem">${node.label}</div>
        ${cmds.join('<hr style="border-color:var(--thermal-22);margin:0.3rem 0">')}`;
      tooltip.classList.add('visible');
      tooltip.style.left = '50%';
      tooltip.style.bottom = '52px';
      tooltip.style.transform = 'translateX(-50%)';
    } else {
      tooltip.classList.remove('visible');
    }

    window.dispatchEvent(new CustomEvent('bt-node-select', { detail: { nodeId, node } }));
  }

  function getEdgeCommands(edge) {
    const MAP = {
      AdminTo: ['psexec', 'wmiexec', 'smbexec'], CanRDP: ['xfreerdp'],
      CanPSRemote: ['evil-winrm'], WriteDacl: ['dacledit'],
      GenericAll: ['password-reset', 'rbcd'], GenericWrite: ['targeted-kerberoast'],
      ForceChangePassword: ['net-user'], AddKeyCredentialLink: ['certipy-shadow', 'pywhisker'],
      WriteAccountRestrictions: ['rbcd-set'], ReadLAPSPassword: ['laps-cme'],
      AllowedToDelegate: ['getST-constrained'], AllowedToAct: ['rbcd-getST'],
      CoerceToTGT: ['petitpotam', 'printerbug'], ExecuteDCOM: ['dcomexec'],
    };
    return MAP[edge] || [];
  }

  function refreshGraph(data) { initGraph(data); }
  return { initGraph, refreshGraph, setLayout, setEdgeFilter };
})();
