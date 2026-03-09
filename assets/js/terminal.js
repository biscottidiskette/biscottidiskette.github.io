/* ---------------------------------------------------------------
   Terminal Component — Biscotti Diskette
   --------------------------------------------------------------- */

function terminalClose(id) {
  var terminal = document.getElementById('terminal-' + id);
  if (terminal) terminal.classList.add('terminal--closed');
}

function terminalMinimize(id) {
  var terminal = document.getElementById('terminal-' + id);
  if (terminal) terminal.classList.toggle('terminal--minimized');
}

function terminalMaximize(id) {
  var overlay = document.getElementById('overlay-' + id);
  if (overlay) overlay.classList.add('terminal__overlay--open');
  document.body.style.overflow = 'hidden';
}

function terminalOverlayClose(id) {
  var overlay = document.getElementById('overlay-' + id);
  if (overlay) overlay.classList.remove('terminal__overlay--open');
  document.body.style.overflow = '';
}

function terminalCopy(id) {
  var body = document.getElementById('terminal-body-' + id);
  if (!body) return;
  navigator.clipboard.writeText(body.innerText).then(function() {
    terminalCopyFeedback(id);
  }).catch(function() {
    var ta = document.createElement('textarea');
    ta.value = body.innerText;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    terminalCopyFeedback(id);
  });
}

function terminalCopyModal(id) {
  var body = document.getElementById('terminal-modal-body-' + id);
  if (!body) return;
  navigator.clipboard.writeText(body.innerText).then(function() {
    terminalCopyFeedback(id);
  }).catch(function() {
    var ta = document.createElement('textarea');
    ta.value = body.innerText;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
    terminalCopyFeedback(id);
  });
}

function terminalCopyFeedback(id) {
  var buttons = document.querySelectorAll('#terminal-' + id + ' .terminal__copy, #overlay-' + id + ' .terminal__copy');
  buttons.forEach(function(btn) {
    var label = btn.querySelector('.terminal__copy-label');
    if (label) {
      btn.classList.add('terminal__copy--copied');
      label.textContent = 'copied!';
      setTimeout(function() {
        btn.classList.remove('terminal__copy--copied');
        label.textContent = 'copy';
      }, 2000);
    }
  });
}

/* Close overlay on Escape key */
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    document.querySelectorAll('.terminal__overlay--open').forEach(function(overlay) {
      overlay.classList.remove('terminal__overlay--open');
    });
    document.body.style.overflow = '';
  }
});