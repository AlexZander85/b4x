import clsx from "clsx";
import Heading from "@theme/Heading";
import Link from "@docusaurus/Link";
import Translate from "@docusaurus/Translate";
import styles from "./styles.module.css";
import { JSX } from "react";

type DocSection = {
  titleId: string;
  titleDefault: string;
  descriptionId: string;
  descriptionDefault: string;
  link: string;
};

const DocSections: DocSection[] = [
  {
    titleId: "home.section.intro.title",
    titleDefault: "Introduction",
    descriptionId: "home.section.intro.desc",
    descriptionDefault:
      "What b4 is, how censorship bypass works, and what you need to start.",
    link: "/docs/intro",
  },
  {
    titleId: "home.section.install.title",
    titleDefault: "Installation",
    descriptionId: "home.section.install.desc",
    descriptionDefault:
      "Install on Linux, OpenWRT, ASUS Merlin, Keenetic, MikroTik, and Docker.",
    link: "/docs/install/",
  },
  {
    titleId: "home.section.quickstart.title",
    titleDefault: "Quickstart",
    descriptionId: "home.section.quickstart.desc",
    descriptionDefault:
      "From first launch to a working bypass in 5 minutes via the web UI.",
    link: "/docs/quickstart",
  },
  {
    titleId: "home.section.sets.title",
    titleDefault: "Sets",
    descriptionId: "home.section.sets.desc",
    descriptionDefault:
      "Bypass configuration bundles: targets, TCP/UDP strategies, routing.",
    link: "/docs/sets/",
  },
];

function DocCard({
  titleId,
  titleDefault,
  descriptionId,
  descriptionDefault,
  link,
}: DocSection) {
  return (
    <div className={clsx("col col--6")}>
      <div className={styles.docCard}>
        <Heading as="h3">
          <Link to={link}>
            <Translate id={titleId}>{titleDefault}</Translate>
          </Link>
        </Heading>
        <p>
          <Translate id={descriptionId}>{descriptionDefault}</Translate>
        </p>
      </div>
    </div>
  );
}

export default function HomepageFeatures() {
  return (
    <section className={styles.features}>
      <div className="container">
        <Heading as="h2" className={styles.sectionTitle}>
          <Translate id="home.section.heading">Documentation</Translate>
        </Heading>
        <div className="row">
          {DocSections.map((props, idx) => (
            <DocCard key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
