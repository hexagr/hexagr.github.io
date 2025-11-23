document.addEventListener('DOMContentLoaded', () => {
  const buttons = document.querySelectorAll('.upvote-button');
  const workerUrl = 'https://long-disk-c26b.hexagramlabs.workers.dev';

  // Helper to get cookie by name
  const getCookie = (name) => {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    return parts.length === 2 ? parts.pop().split(';').shift() : null;
  };

  buttons.forEach(button => {
    const postId = button.getAttribute('data-post-id');
    const countElement = button.nextElementSibling;

    // Fetch initial upvote count
    fetch(`${workerUrl}/${encodeURIComponent(postId)}`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    })
      .then(response => response.json())
      .then(data => {
        countElement.textContent = `${data.upvotes} Toasts`;
      })
      .catch(error => {
        console.error('Error fetching upvotes:', error);
        countElement.textContent = `${data.upvotes} Toasts`;
      });

    // Handle button click
    button.addEventListener('click', () => {
      // Check if user has already voted via cookie
      if (getCookie(`voted_${postId}`) === 'true') {
        return; // Silent return, no UI change
      }

      fetch(`${workerUrl}/${encodeURIComponent(postId)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      })
        .then(response => {
          if (response.status === 403 || response.status === 429) {
            return; // Silent return for repeat or rate-limited votes
          }
          if (!response.ok) {
            throw new Error('Failed to upvote');
          }
          return response.json();
        })
        .then(data => {
          if (data && data.upvotes !== undefined) {
            countElement.textContent = `${data.upvotes} Toasts`;
          }
        })
        .catch(error => {
          console.error('Error submitting upvote:', error);
          countElement.textContent = `${data.upvotes} Toasts`;
        });
    });
  });
});
