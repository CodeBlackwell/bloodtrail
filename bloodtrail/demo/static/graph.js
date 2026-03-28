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

  // Pre-built reverse lookup: edge type → category (O(1) instead of iterating all sets)
  const EDGE_CAT_LOOKUP = {};
  for (const [cat, set] of Object.entries(EDGE_CATS)) {
    for (const type of set) EDGE_CAT_LOOKUP[type] = cat;
  }

  function edgeCategory(type) {
    return EDGE_CAT_LOOKUP[type] || 'other';
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

  // HTML-escape untrusted strings before innerHTML insertion
  function esc(s) {
    if (typeof s !== 'string') return '';
    return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
          return -(s + 6);
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
    window._btLeftNodeGs = leftNodeGs;
    window._btLeftEdgeGs = leftEdgeGs;
    window._btRightEdgeGs = rightEdgeGs;
    window._btNodes = nodes;
    window._btEdges = edges;
    _attackConnectedCache = null; // invalidate on new data

    // Click
    leftNodeGs.on('click', (e, d) => selectNode(d.id));
    rightNodeGs.on('click', (e, d) => selectNode(d.id));

    layoutW = w;
    layoutH = h;

    // Tick helpers — extracted to avoid closure allocation per frame
    function curvePath(d) {
      const dx = d.target.x - d.source.x;
      const dy = d.target.y - d.source.y;
      const dr = Math.sqrt(dx * dx + dy * dy) * 1.5;
      return `M${d.source.x},${d.source.y}A${dr},${dr} 0 0,1 ${d.target.x},${d.target.y}`;
    }
    function labelPosX(d) {
      const dx = d.target.x - d.source.x, dy = d.target.y - d.source.y;
      const len = Math.sqrt(dx*dx + dy*dy) || 1;
      return (d.source.x + d.target.x) / 2 - (dy/len)*8;
    }
    function labelPosY(d) {
      const dx = d.target.x - d.source.x, dy = d.target.y - d.source.y;
      const len = Math.sqrt(dx*dx + dy*dy) || 1;
      return (d.source.y + d.target.y) / 2 + (dx/len)*8;
    }
    function nodeTransform(d) { return `translate(${d.x}px,${d.y}px)`; }

    // Simulation — forces configured by layout mode
    simulation = d3.forceSimulation(nodes)
      .alphaDecay(0.05)
      .force('link', d3.forceLink(edges).id(d => d.id))
      .force('collide', d3.forceCollide(16));

    _applyLayout(currentLayout);

    // Reusable objects to reduce GC pressure in tick loop
    let _tickFrame = 0;

    simulation.on('tick', () => {
        _tickFrame++;
        // Curved edges — both panels share same node positions
        leftPaths.attr('d', curvePath);
        rightPaths.attr('d', curvePath);

        // Edge labels — only update every 3rd tick (they drift slowly, invisible cost)
        if (_tickFrame % 3 === 0) {
          rightEdgeLabels.attr('x', labelPosX).attr('y', labelPosY);
          // Left labels are opacity:0 by default, skip entirely unless hovered
        }

        leftNodeGs.style('transform', nodeTransform);
        rightNodeGs.style('transform', nodeTransform);
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

  // Pre-computed set of nodes connected by attack (non-structural) edges
  let _attackConnectedCache = null;

  function _buildAttackConnected() {
    if (_attackConnectedCache) return _attackConnectedCache;
    const set = new Set();
    if (window._btEdges) {
      const STRUCTURAL = EDGE_CATS.member;
      window._btEdges.forEach(e => {
        if (!STRUCTURAL.has(e.edge)) {
          set.add(typeof e.source === 'object' ? e.source.id : e.source);
          set.add(typeof e.target === 'object' ? e.target.id : e.target);
        }
      });
    }
    _attackConnectedCache = set;
    return set;
  }

  // Edge filter: 'attacks' hides MemberOf/Contains, dims unconnected nodes
  function _applyEdgeFilter(mode) {
    const STRUCTURAL = EDGE_CATS.member;
    const hideStructural = mode === 'attacks';
    const attackConnected = hideStructural ? _buildAttackConnected() : null;

    // Use stored selections instead of global d3.selectAll
    if (window._btLeftEdgeGs) {
      window._btLeftEdgeGs.classed('edge-hidden', d => hideStructural && STRUCTURAL.has(d.edge));
    }
    if (window._btRightEdgeGs) {
      window._btRightEdgeGs.classed('edge-hidden', d => hideStructural && STRUCTURAL.has(d.edge));
    }

    if (window._btRightNodeGs) {
      window._btRightNodeGs.classed('node-dimmed', d => hideStructural && attackConnected && !attackConnected.has(d.id));
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
        const dir = e.source_id === nodeId ? `→ ${esc(shortName(e.target_name))}` : `← ${esc(shortName(e.source_name))}`;
        return `<div class="tool-name">${esc(e.edge)} ${dir}</div><div class="cmd-text">${esc(tools.join(', '))}</div>`;
      }).filter(Boolean).slice(0, 5);

    if (cmds.length) {
      tooltip.innerHTML = `<div class="tool-name" style="font-size:0.8rem;margin-bottom:0.4rem">${esc(node.name)}</div>
        <div style="color:var(--text-faint);font-size:0.6rem;margin-bottom:0.3rem">${esc(node.label)}</div>
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
  return { initGraph, refreshGraph, setLayout, setEdgeFilter, esc };
})();
