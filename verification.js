
    
    
    setTimeout(() => {
      console.log("2 seconds later...");
    }, 2000); // 2000 milliseconds = 2 seconds
    
    // Variables to store user data
    let complaintReceiverName = '';
    let complaintReceiverId = null;

    async function verifyAuthToken() {
      const authToken = localStorage.getItem('authToken');
      
      if (!authToken) {
        console.log('No authToken found in localStorage');
        alert('Authentication failed: No token found');
        window.location.href = 'login.html';
        return;
      }

      try {
        console.log('Attempting to verify authToken...');
        
        const response = await fetch(SERVER_URL+'/verify-token-get-receiver', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${authToken}`
          },
          body: JSON.stringify({
            page_name: page   // 👈 the page name you want to verify
          })
        });

        if (!response.ok) {
          throw new Error(`HTTP error! status: ${response.status}`);
        }

        const data = await response.json();
        console.log('API Response:', data);

        if (data.success) {
          console.log('Token verification successful for user:', data.user.name);

          localStorage.setItem('UserId', data.user.name);
          
          // Store user data in localStorage
          localStorage.setItem('currentUser', JSON.stringify(data.user));
          
          // Store user ID in variable
          complaintReceiverId = data.user.id;
          console.log('Current user ID:', complaintReceiverId);
          
          // Store receiver name
          complaintReceiverName = data.receiver?.name || 'Unknown';
          console.log('Complaint receiver name:', complaintReceiverName);
          
          document.body.style.display = 'block';
          
        } else {
          console.log('Token verification failed:', data.message || 'No error message provided');
          //alert('Authentication failed: ' + (data.message || 'Invalid token'));
          showNotification('Authentication failed: ' + (data.message || 'Invalid token'), 'error');
          localStorage.removeItem('authToken');
          window.location.href = 'login.html';
        }
      } catch (error) {
        console.error('Error during token verification:', error);
        //alert('Authentication failed: ' + error.message);
        showNotification('Authentication failed: ' + error.message, 'error')
        localStorage.removeItem('authToken');
        window.location.href = 'login.html';
      }
    }

    // Call the function when the page loads
    document.addEventListener('DOMContentLoaded', verifyAuthToken);