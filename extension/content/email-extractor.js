/** Extract visible email fields from an opened Gmail message. */

function extractOpenEmail() {
  const subjectEl =
    document.querySelector("h2.hP") ||
    document.querySelector("[data-thread-perm-id] h2") ||
    document.querySelector(".ha h2");

  const senderEl =
    document.querySelector("span.gD") ||
    document.querySelector("[email].gD") ||
    document.querySelector(".gD[email]");

  const bodyEl =
    document.querySelector(".a3s.aiL") ||
    document.querySelector(".a3s") ||
    document.querySelector("[data-message-id] .a3s");

  const subject = subjectEl?.innerText?.trim() || "";
  const sender =
    senderEl?.getAttribute("email") ||
    senderEl?.getAttribute("data-hovercard-id") ||
    senderEl?.innerText?.trim() ||
    "";
  const body = bodyEl?.innerText?.trim() || "";

  const links = [];
  bodyEl?.querySelectorAll("a[href]")?.forEach((a) => {
    links.push({ href: a.href, text: a.innerText?.trim() || "" });
  });

  return {
    subject,
    sender,
    body,
    links,
    url: location.href,
  };
}

window.PhishGuardExtract = { extractOpenEmail };
