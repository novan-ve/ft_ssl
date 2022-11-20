/* ************************************************************************** */
/*                                                                            */
/*                                                        ::::::::            */
/*   ft_printx.c                                        :+:    :+:            */
/*                                                     +:+                    */
/*   By: novan-ve <novan-ve@student.codam.nl>         +#+                     */
/*                                                   +#+                      */
/*   Created: 2019/12/27 16:07:12 by novan-ve      #+#    #+#                 */
/*   Updated: 2022/09/28 13:55:05 by novan-ve      ########   odam.nl         */
/*                                                                            */
/* ************************************************************************** */

#include "libft.h"

void	ft_printx3(t_print *p, int x)
{
	int		i;

	i = 0;
	if (x == 0)
		if (p->just == 'l')
			while (i < p->tmpwidth - p->tmplen && i < p->tmpwidth - p->prec)
			{
				p->len++;
				ft_putchar_fd(p->padchar, p->fd);
				i++;
			}
	if (x == 1)
		if (p->just == 'r')
			while (i < p->tmpwidth - p->tmplen && i < p->tmpwidth - p->prec)
			{
				p->len++;
				ft_putchar_fd(p->padchar, p->fd);
				i++;
			}
}

void	ft_printx2(t_print *p)
{
	int		i;

	ft_printx3(p, 0);
	i = 0;
	while (i < (p->prec - p->tmplen))
	{
		p->len++;
		ft_putchar_fd('0', p->fd);
		i++;
	}
	ft_putstr_fd(p->hex, p->fd);
	ft_printx3(p, 1);
}

void	ft_printx(t_print *p, int x)
{
	ft_dec_to_hex(p, va_arg(p->args, unsigned long), x, 16);
	if (p->hex[0] == '\0' && p->prec != 0)
	{
		p->hex[0] = '0';
		p->hex[1] = '\0';
		p->tmplen = 1;
	}
	if (p->tmplen < p->tmpwidth || p->prec != -1)
		ft_printx2(p);
	else
		ft_putstr_fd(p->hex, p->fd);
}
