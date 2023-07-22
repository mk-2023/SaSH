﻿/*
				GNU GENERAL PUBLIC LICENSE
				   Version 2, June 1991
COPYRIGHT (C) Bestkakkoii 2023 All Rights Reserved.
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.

*/

#include "stdafx.h"
#include "selecttargetform.h"
#include <util.h>
#include <injector.h>

SelectTargetForm::SelectTargetForm(int type, QString* dst, QWidget* parent)
	: QDialog(parent), type_(type), dst_(dst)
{
	ui.setupUi(this);
	setAttribute(Qt::WA_DeleteOnClose);
	setWindowFlags(Qt::Tool | Qt::Dialog | Qt::WindowCloseButtonHint);
	setModal(true);
	connect(ui.buttonBox, &QDialogButtonBox::accepted, this, &SelectTargetForm::onAccept);
	connect(ui.buttonBox, &QDialogButtonBox::rejected, this, &QDialog::reject);

	ui.buttonBox->button(QDialogButtonBox::Ok)->setText(tr("ok"));
	ui.buttonBox->button(QDialogButtonBox::Cancel)->setText(tr("cancel"));

	QList <QCheckBox*> checkBoxList = util::findWidgets<QCheckBox>(this);
	for (auto& checkBox : checkBoxList)
	{
		if (checkBox)
			connect(checkBox, &QCheckBox::stateChanged, this, &SelectTargetForm::onCheckBoxStateChanged, Qt::UniqueConnection);
	}

	Injector& injector = Injector::getInstance();
	selectflag_ = static_cast<unsigned int>(injector.getValueHash(static_cast<util::UserSetting>(type)));
	checkControls();

	const QHash<int, QString> title_hash = {
		//afk->battle button
		{ util::kBattleCharRoundActionTargetValue, tr("player specific round action") },
		{ util::kBattleCharCrossActionTargetValue, tr("Player alternating round action") },
		{ util::kBattleCharNormalActionTargetValue, tr("player normal round action") },

		{ util::kBattlePetRoundActionTargetValue, tr("pet specific round action") },
		{ util::kBattlePetCrossActionTargetValue, tr("pet alternating round action") },
		{ util::kBattlePetNormalActionTargetValue, tr("pet normal round action") },

		//afk->heal button
		{ util::kBattleMagicHealTargetValue, tr("magic healing target") },
		{ util::kBattleItemHealTargetValue, tr("item healing target") },
		{ util::kBattleMagicReviveTargetValue, tr("magic revival target") },
		{ util::kBattleItemReviveTargetValue, tr("item revival target") },
	};

	setWindowTitle(title_hash.value(type_, tr("unknown")));
}

SelectTargetForm::~SelectTargetForm()
{
}

void SelectTargetForm::showEvent(QShowEvent* e)
{
	setAttribute(Qt::WA_Mapped);
	QDialog::showEvent(e);
}

void SelectTargetForm::onAccept()
{
	if (dst_)
	{
		*dst_ = generateShortName(selectflag_);
		Injector& injector = Injector::getInstance();
		injector.setValueHash(static_cast<util::UserSetting>(type_), selectflag_);
	}
	accept();
}

void SelectTargetForm::checkControls()
{
	ui.checkBox_self->setChecked(selectflag_ & util::kSelectSelf);
	ui.checkBox_pet->setChecked(selectflag_ & util::kSelectPet);
	ui.checkBox_any->setChecked(selectflag_ & util::kSelectAllieAny);
	ui.checkBox_all->setChecked(selectflag_ & util::kSelectAllieAll);
	ui.checkBox_enemy->setChecked(selectflag_ & util::kSelectEnemyAny);
	ui.checkBox_enemy_all->setChecked(selectflag_ & util::kSelectEnemyAll);
	ui.checkBox_enemy_front->setChecked(selectflag_ & util::kSelectEnemyFront);
	ui.checkBox_enemy_back->setChecked(selectflag_ & util::kSelectEnemyBack);
	ui.checkBox_leader->setChecked(selectflag_ & util::kSelectLeader);
	ui.checkBox_leader_pet->setChecked(selectflag_ & util::kSelectLeaderPet);
	ui.checkBox_teammate1->setChecked(selectflag_ & util::kSelectTeammate1);
	ui.checkBox_teammate1_pet->setChecked(selectflag_ & util::kSelectTeammate1Pet);
	ui.checkBox_teammate2->setChecked(selectflag_ & util::kSelectTeammate2);
	ui.checkBox_teammate2_pet->setChecked(selectflag_ & util::kSelectTeammate2Pet);
	ui.checkBox_teammate3->setChecked(selectflag_ & util::kSelectTeammate3);
	ui.checkBox_teammate3_pet->setChecked(selectflag_ & util::kSelectTeammate3Pet);
	ui.checkBox_teammate4->setChecked(selectflag_ & util::kSelectTeammate4);
	ui.checkBox_teammate4_pet->setChecked(selectflag_ & util::kSelectTeammate4Pet);
}

void SelectTargetForm::onCheckBoxStateChanged(int state)
{
	QCheckBox* pCheckBox = qobject_cast<QCheckBox*>(sender());
	if (!pCheckBox)
		return;

	bool isChecked = (state == Qt::Checked);

	QString name = pCheckBox->objectName();
	if (name.isEmpty())
		return;

	//Injector& injector = Injector::getInstance();

	unsigned int tempFlg = 0u;

	if (name == "checkBox_self")
	{
		tempFlg = util::kSelectSelf;
	}
	else if (name == "checkBox_pet")
	{
		tempFlg = util::kSelectPet;
	}
	else if (name == "checkBox_any")
	{
		tempFlg = util::kSelectAllieAny;
	}
	else if (name == "checkBox_all")
	{
		tempFlg = util::kSelectAllieAll;
	}
	else if (name == "checkBox_enemy")
	{
		tempFlg = util::kSelectEnemyAny;
	}
	else if (name == "checkBox_enemy_all")
	{
		tempFlg = util::kSelectEnemyAll;
	}
	else if (name == "checkBox_enemy_front")
	{
		tempFlg = util::kSelectEnemyFront;
	}
	else if (name == "checkBox_enemy_back")
	{
		tempFlg = util::kSelectEnemyBack;
	}

	else if (name == "checkBox_leader")
	{
		tempFlg = util::kSelectLeader;
	}
	else if (name == "checkBox_leader_pet")
	{
		tempFlg = util::kSelectLeaderPet;
	}
	else if (name == "checkBox_teammate1")
	{
		tempFlg = util::kSelectTeammate1;
	}
	else if (name == "checkBox_teammate1_pet")
	{
		tempFlg = util::kSelectTeammate1Pet;
	}
	else if (name == "checkBox_teammate2")
	{
		tempFlg = util::kSelectTeammate2;
	}
	else if (name == "checkBox_teammate2_pet")
	{
		tempFlg = util::kSelectTeammate2Pet;
	}
	else if (name == "checkBox_teammate3")
	{
		tempFlg = util::kSelectTeammate3;
	}
	else if (name == "checkBox_teammate3_pet")
	{
		tempFlg = util::kSelectTeammate3Pet;
	}
	else if (name == "checkBox_teammate4")
	{
		tempFlg = util::kSelectTeammate4;
	}
	else if (name == "checkBox_teammate4_pet")
	{
		tempFlg = util::kSelectTeammate4Pet;
	}

	if (isChecked)
	{
		selectflag_ |= tempFlg;
	}
	else
	{
		selectflag_ &= ~tempFlg;
	}
}

QString SelectTargetForm::generateShortName(unsigned int flg)
{
	QString shortName;
	if (flg & util::kSelectSelf)
	{
		shortName += tr("S");  // 己 (Self)
	}
	if (flg & util::kSelectPet)
	{
		shortName += tr("P");  // 寵 (Pet)
	}
	if (flg & util::kSelectAllieAny)
	{
		shortName += tr("ANY");  // 我任 (Any ally)
	}
	if (flg & util::kSelectAllieAll)
	{
		shortName += tr("ALL");  // 我全 (All allies)
	}
	if (flg & util::kSelectEnemyAny)
	{
		shortName += tr("EANY");  // 敵任 (Any enemy)
	}
	if (flg & util::kSelectEnemyAll)
	{
		shortName += tr("EALL");  // 敵全 (All enemies)
	}
	if (flg & util::kSelectEnemyFront)
	{
		shortName += tr("EF");  // 敵前 (Front enemy)
	}
	if (flg & util::kSelectEnemyBack)
	{
		shortName += tr("EB");  // 敵後 (Back enemy)
	}
	if (flg & util::kSelectLeader)
	{
		shortName += tr("L");  // 隊 (Leader)
	}
	if (flg & util::kSelectLeaderPet)
	{
		shortName += tr("LP");  // 隊寵 (Leader's pet)
	}
	if (flg & util::kSelectTeammate1)
	{
		shortName += tr("T1");  // 隊1 (Teammate 1)
	}
	if (flg & util::kSelectTeammate1Pet)
	{
		shortName += tr("T1P");  // 隊1寵 (Teammate 1's pet)
	}
	if (flg & util::kSelectTeammate2)
	{
		shortName += tr("T2");  // 隊2 (Teammate 2)
	}
	if (flg & util::kSelectTeammate2Pet)
	{
		shortName += tr("T2P");  // 隊2寵 (Teammate 2's pet)
	}
	if (flg & util::kSelectTeammate3)
	{
		shortName += tr("T3");  // 隊3 (Teammate 3)
	}
	if (flg & util::kSelectTeammate3Pet)
	{
		shortName += tr("T3P");  // 隊3寵 (Teammate 3's pet)
	}
	if (flg & util::kSelectTeammate4)
	{
		shortName += tr("T4");  // 隊4 (Teammate 4)
	}
	if (flg & util::kSelectTeammate4Pet)
	{
		shortName += tr("T4P");  // 隊4寵 (Teammate 4's pet)
	}

	return shortName;
}