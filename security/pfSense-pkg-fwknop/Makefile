# $FreeBSD$

PORTNAME=	pfSense-pkg-fwknop
PORTVERSION=	0.1.0
CATEGORIES=	security
MASTER_SITES=	# empty
DISTFILES=	# empty
EXTRACT_ONLY=	# empty

MAINTAINER=	coreteam@pfsense.org
COMMENT=	pfSense package fwknop Single Packet Authorization

LICENSE=	APACHE20

RUN_DEPENDS=	${LOCALBASE}/sbin/fwknopd:security/fwknop

NO_BUILD=	yes
NO_MTREE=	yes

SUB_FILES=	pkg-install pkg-deinstall
SUB_LIST=	PORTNAME=${PORTNAME}

do-extract:
	${MKDIR} ${WRKSRC}

do-install:
	${MKDIR} ${STAGEDIR}${PREFIX}/pkg
	${MKDIR} ${STAGEDIR}${DATADIR}
	${MKDIR} ${STAGEDIR}/etc/inc/priv
	${MKDIR} ${STAGEDIR}${PREFIX}/www/packages/fwknop
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/fwknop.xml \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/pkg/fwknop.inc \
		${STAGEDIR}${PREFIX}/pkg
	${INSTALL_DATA} ${FILESDIR}/etc/inc/priv/fwknop.priv.inc \
		${STAGEDIR}/etc/inc/priv
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/packages/fwknop/index.php \
		${STAGEDIR}${PREFIX}/www/packages/fwknop
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/packages/fwknop/edit.php \
		${STAGEDIR}${PREFIX}/www/packages/fwknop
	${INSTALL_DATA} ${FILESDIR}${PREFIX}/www/packages/fwknop/status.php \
		${STAGEDIR}${PREFIX}/www/packages/fwknop
	${INSTALL_DATA} ${FILESDIR}${DATADIR}/info.xml \
		${STAGEDIR}${DATADIR}
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${DATADIR}/info.xml
	@${REINPLACE_CMD} -i '' -e "s|%%PKGVERSION%%|${PKGVERSION}|" \
		${STAGEDIR}${PREFIX}/pkg/fwknop.xml

.include <bsd.port.mk>
