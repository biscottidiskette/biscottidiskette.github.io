---
layout: page
permalink: /contact/
title: contact
description: Feel free to send me a message!. 
nav: true
nav_order: 6
---

<!-- Social / Profile Links -->
<div style="display:flex; gap:1.5rem; justify-content:center; margin-bottom:2.5rem; flex-wrap:wrap;">
  <a href="https://github.com/biscottidiskette" target="_blank" rel="noopener"
     style="display:flex; align-items:center; gap:0.5rem; color:#eee; text-decoration:none; font-size:1rem; font-weight:500; padding:0.6rem 1.2rem; border:1px solid #333; border-radius:6px; background:#1e1e1e; transition:border-color 0.2s, color 0.2s;"
     onmouseover="this.style.borderColor='#ff4500';this.style.color='#ff4500';"
     onmouseout="this.style.borderColor='#333';this.style.color='#eee';">
    <i class="fa-brands fa-github"></i> GitHub
  </a>
  <a href="https://app.hackthebox.eu/profile/biscottidiskette" target="_blank" rel="noopener"
     style="display:flex; align-items:center; gap:0.5rem; color:#eee; text-decoration:none; font-size:1rem; font-weight:500; padding:0.6rem 1.2rem; border:1px solid #333; border-radius:6px; background:#1e1e1e; transition:border-color 0.2s, color 0.2s;"
     onmouseover="this.style.borderColor='#ff4500';this.style.color='#ff4500';"
     onmouseout="this.style.borderColor='#333';this.style.color='#eee';">
    <i class="fa-solid fa-cube"></i> HackTheBox
  </a>
  <a href="https://tryhackme.com/r/p/BiscottiDiskette" target="_blank" rel="noopener"
     style="display:flex; align-items:center; gap:0.5rem; color:#eee; text-decoration:none; font-size:1rem; font-weight:500; padding:0.6rem 1.2rem; border:1px solid #333; border-radius:6px; background:#1e1e1e; transition:border-color 0.2s, color 0.2s;"
     onmouseover="this.style.borderColor='#ff4500';this.style.color='#ff4500';"
     onmouseout="this.style.borderColor='#333';this.style.color='#eee';">
    <i class="fa-solid fa-flag"></i> TryHackMe
  </a>
</div>
<!-- Contact Form -->
<section style="max-width:600px; margin:0 auto; padding:2rem; background:#1a1a1a; border:1px solid #333; border-radius:0.75rem; color:#fff;">
  <form id="contactForm" action="https://formspree.io/f/mblzloyw" method="POST" style="display:flex; flex-direction:column; gap:1rem;">
    <input type="text" name="name" placeholder="Your Name" required
           style="padding:0.75rem 1rem; border-radius:0.5rem; border:1px solid #333; background:#222; color:#fff; font-size:0.95rem; outline:none; font-family:'JetBrains Mono', monospace;"
           onfocus="this.style.borderColor='#ff4500'" onblur="this.style.borderColor='#333'">
<input type="email" name="email" placeholder="Your Email" required
       style="padding:0.75rem 1rem; border-radius:0.5rem; border:1px solid #333; background:#222; color:#fff; font-size:0.95rem; outline:none; font-family:'JetBrains Mono', monospace;"
       onfocus="this.style.borderColor='#ff4500'" onblur="this.style.borderColor='#333'">

<textarea name="message" placeholder="Your Message" required rows="5"
          style="padding:0.75rem 1rem; border-radius:0.5rem; border:1px solid #333; background:#222; color:#fff; font-size:0.95rem; outline:none; font-family:'JetBrains Mono', monospace; resize:vertical;"
          onfocus="this.style.borderColor='#ff4500'" onblur="this.style.borderColor='#333'"></textarea>

<button type="submit"
        style="padding:0.75rem 1.5rem; background:#ff4500; color:#fff; font-size:0.95rem; font-weight:600; border:none; border-radius:0.5rem; cursor:pointer; transition:background 0.2s;"
        onmouseover="this.style.background='#cc3700'" onmouseout="this.style.background='#ff4500'">
  Send Message
</button>

<p id="formMessage" style="text-align:center; margin-top:0.5rem; font-size:0.95rem; display:none;"></p>
  </form>
</section>
<script>
  const form = document.getElementById('contactForm');
  const formMessage = document.getElementById('formMessage');

  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const formData = new FormData(form);
    const response = await fetch(form.action, {
      method: 'POST',
      body: formData,
      headers: { 'Accept': 'application/json' }
    });

    if (response.ok) {
      formMessage.style.display = 'block';
      formMessage.style.color = '#00FF00';
      formMessage.textContent = 'Thank you! Your message has been sent.';
      form.reset();
    } else {
      formMessage.style.display = 'block';
      formMessage.style.color = '#FF5555';
      formMessage.textContent = 'Oops! Something went wrong. Please try again.';
    }
  });
</script>