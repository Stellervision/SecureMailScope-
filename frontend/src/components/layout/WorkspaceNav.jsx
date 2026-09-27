function WorkspaceNav({
  activeView,
  setActiveView,
}) {
  return (
    <nav className="workspace-nav">
      <button
        className={
          activeView === "inbox"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView("inbox")
        }
      >
        Inbox
      </button>

      <button
        className={
          activeView === "sent"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView("sent")
        }
      >
        Sent
      </button>

      <button
        className={
          activeView === "compose"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView("compose")
        }
      >
        Compose
      </button>

      <button
        className={
          activeView === "security"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView("security")
        }
      >
        Security
      </button>

      <button
        className={
          activeView === "forensics"
            ? "active"
            : ""
        }
        onClick={() =>
          setActiveView("forensics")
        }
      >
        Forensics
      </button>
    </nav>
  );
}

export default WorkspaceNav;