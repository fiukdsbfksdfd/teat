export default async function handler(req, res) {
  const html = `
<!DOCTYPE html>
<html>
<head>
<title>ENDPOINT DISCONTINUED</title>
<style>
  body {
    font-family: Arial;
    background: #000;
    color: #fff;
    display: flex;
    justify-content: center;
    align-items: center;
    height: 100vh;
    margin: 0;
  }
  h1 {
    font-size: 50px;
  }
</style>
</head>
<body>
<h1>ENDPOINT DISCONTINUED</h1>
</body>
</html>
  `;

  res.setHeader("Content-Type", "text/html");
  res.status(200).send(html);
}
