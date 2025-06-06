// Load Firebase libraries dynamically
const loadFirebase = async () => {
  const firebaseApp = document.createElement("script");
  firebaseApp.src = "https://www.gstatic.com/firebasejs/10.12.0/firebase-app.js";
  document.head.appendChild(firebaseApp);

  const firebaseAuth = document.createElement("script");
  firebaseAuth.src = "https://www.gstatic.com/firebasejs/10.12.0/firebase-auth.js";
  document.head.appendChild(firebaseAuth);

  await new Promise((resolve) => {
    firebaseAuth.onload = resolve;
  });

  // Initialize Firebase (fill in YOUR actual values)
  const firebaseConfig = {
    apiKey: "AIzaSyDdrj7bG7Nl_B63ReKOtgKO8xK-KRlVpgA",
    authDomain: "emailytics-firebase.firebaseapp.com",
    projectId: "emailytics-firebase",
    appId: "1:133361977705:web:ad9eb91018c8ebd09495f8",
  };

  firebase.initializeApp(firebaseConfig);
  const auth = firebase.auth();

  // Google Sign-In
  const loginWithGoogle = async () => {
    const provider = new firebase.auth.GoogleAuthProvider();
    try {
      const result = await auth.signInWithPopup(provider);
      const user = result.user;
      const idToken = await user.getIdToken();

      // Send ID token to your backend
      await fetch("https://your-backend-url.com/api/auth", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${idToken}`,
        },
        body: JSON.stringify({ email: user.email }),
      });

      alert("Logged in!");
    } catch (err) {
      console.error("Login failed", err);
    }
  };

  // Attach to Webflow button
  document.addEventListener("DOMContentLoaded", function () {
    const loginButton = document.getElementById("login-button");
    if (loginButton) {
      loginButton.addEventListener("click", loginWithGoogle);
    }
  });
};

loadFirebase();
