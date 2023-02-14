// Copyright (c) Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

import { ReactComponent as SuiLogoIcon } from '../../assets/Sui Logo.svg';
import { type FooterItems, footerLinks } from './footerLinks';

import { Link } from '~/ui/Link';
import { Text } from '~/ui/Text';

function FooterLinks({ links }: { links: FooterItems }) {
    return (
        <>
            {links.map(({ category, items }) => (
                <div
                    key={category}
                    className="flex flex-col gap-y-3.5 text-left"
                >
                    <Text variant="captionSmall/bold" color="gray-60">
                        {category}
                    </Text>
                    <ul className="flex flex-col gap-y-3.5">
                        {items.map(({ title, href }) => (
                            <li key={href}>
                                <Link variant="text" href={href}>
                                    <Text variant="body/medium" color="white">
                                        {title}
                                    </Text>
                                </Link>
                            </li>
                        ))}
                    </ul>
                </div>
            ))}
        </>
    );
}

function Footer() {
    return (
        <footer className="bg-gray-75 p-5 md:p-14">
            <nav className="mx-auto grid grid-cols-1 items-center justify-center text-left xl:grid-cols-2">
                <div className="grid grid-cols-4 md:grid-cols-5">
                    <div className="hidden h-full flex-col md:flex">
                        <SuiLogoIcon />
                        <div className="mt-7.5">
                            <Text color="white" variant="p4/semibold">
                                &copy;{`${new Date().getFullYear()} Sui`}
                            </Text>
                            <Text color="white" variant="p4/semibold">
                                All rights reserved
                            </Text>
                        </div>
                    </div>
                    <FooterLinks links={footerLinks} />
                </div>
            </nav>
        </footer>
    );
}

export default Footer;
