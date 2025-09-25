---
layout: page
permalink: /contact/
title: contact
description: Feel free to send me a message!. 
nav: true
nav_order: 10
---

<section class="contact-form" style="max-width:600px; margin:3rem auto; padding:2rem; background:#1a1a1a; border-radius:0.75rem; color:#fff;">
  <h2 style="font-size:2rem; margin-bottom:1rem; text-align:center;">Contact Me</h2>
  <p style="font-size:1.1rem; color:#ccc; text-align:center; margin-bottom:2rem;">
    Have a question or want to collaborate? Send me a message!
  </p>

  <form id="contactForm" action="https://formspree.io/f/mblzloyw" method="POST" style="display:flex; flex-direction:column; gap:1rem;">
    <input type="text" name="name" placeholder="Your Name" required
           style="padding:0.75rem 1rem; border-radius:0.5rem; border:1px solid #444; background:#222; color:#fff; font-size:1rem;">
    
    <input type="email" name="email" placeholder="Your Email" required
           style="padding:0.75rem 1rem; border-radius:0.5rem; border:1px solid #444; background:#222; color:#fff; font-size:1rem;">
    
    <textarea name="message" placeholder="Your Message" required rows="5"
              style="padding:0.75rem 1rem; border-radius:0.5rem; border:1px solid #444; background:#222; color:#fff; font-size:1rem;"></textarea>
    
    <button type="submit" 
            style="padding:0.75rem 1.5rem; background:#007BFF; color:#fff; font-size:1rem; border:none; border-radius:0.5rem; cursor:pointer; transition:background 0.2s;">
      Send Message
    </button>

    <p id="formMessage" style="text-align:center; margin-top:1rem; font-size:1rem; display:none;"></p>
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