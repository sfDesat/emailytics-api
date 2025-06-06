<!-- Load Firebase libraries -->
<script src="https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js"></script>
<script src="https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js"></script>

<script>
  // STEP 1: Initialize Firebase (fill in with YOUR values from the Firebase snippet)
  const firebaseConfig = {
    apiKey: "AIzaSyDdrj7bG7Nl_B63ReKOtgKO8xK-KRlVpgA",
    authDomain: "emailytics-firebase.firebaseapp.com",
    projectId: "emailytics-firebase",
    appId: "1:133361977705:web:ad9eb91018c8ebd09495f8",
  };

  firebase.initializeApp(firebaseConfig);
  const auth = firebase.auth();

  // STEP 2: Google Login Function
  async function loginWithGoogle() {
    const provider = new firebase.auth.GoogleAuthProvider();
    try {
      const result = await auth.signInWithPopup(provider);
      const user = result.user;
      const idToken = await user.getIdToken();

      // STEP 3: Send ID token to your backend
      await fetch("https://your-backend-url.com/api/auth", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${idToken}`,
        },
        body: JSON.stringify({ email: user.email }),
      });

      // Redirect or show success message
      alert("Logged in!");
    } catch (err) {
      console.error("Login failed", err);
    }
  }

  // STEP 4: Attach to button in Webflow
  document.addEventListener("DOMContentLoaded", function () {
    const loginButton = document.getElementById("login-button");
    if (loginButton) {
      loginButton.addEventListener("click", loginWithGoogle);
    }
  });
</script>
